/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Isolated interoperability peer. TLS uses OpenSSL; signed witness commands
 * remain opaque and are dispatched by the separate authenticated store host.
 * No production provisioning, witness storage, signature or retry API. */
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const unsigned char protocol[] = "q-periapt-anchor/1";
enum { REQUEST = 3674, REPLY = 3659, SUBJECT = 96, MAX_FILE = 8192 };
struct binding { X509 *certificate; unsigned char subject[SUBJECT]; };
static _Noreturn void die(const char *message) {
    fprintf(stderr, "OPENSSL_WITNESS_ERROR %s\n", message);
    ERR_print_errors_fp(stderr);
    exit(1);
}
static void require(int condition, const char *message) { if (!condition) die(message); }
static int64_t millis(void) {
    struct timespec now;
    require(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock");
    require(now.tv_sec <= INT64_MAX / 1000, "clock range");
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static void ready(int fd, short events, int64_t deadline) {
    for (;;) {
        int64_t left = deadline - millis();
        require(left > 0 && left <= 10000, "absolute operation deadline");
        struct pollfd item = { .fd = fd, .events = events, .revents = 0 };
        int result = poll(&item, 1, (int)left);
        if (result < 0 && errno == EINTR) continue;
        require(result > 0 && !(item.revents & POLLNVAL), "socket/pipe readiness");
        return; /* The subsequent I/O diagnoses HUP/ERR, never treats it as data. */
    }
}
static void nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    require(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0, "nonblocking descriptor");
}
static void io_exact(int fd, unsigned char *bytes, size_t length, int writing, int64_t deadline) {
    size_t done = 0;
    while (done < length) {
        ready(fd, writing ? POLLOUT : POLLIN, deadline);
        ssize_t count = writing ? write(fd, bytes + done, length - done) : read(fd, bytes + done, length - done);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        require(count > 0, "incomplete IPC frame");
        done += (size_t)count;
    }
}
static void prefix(unsigned char out[4], size_t length) {
    require(length <= UINT32_MAX, "frame length");
    uint32_t value = htonl((uint32_t)length); memcpy(out, &value, 4);
}
static void check_prefix(const unsigned char bytes[4], size_t length) {
    uint32_t value; memcpy(&value, bytes, 4);
    require(ntohl(value) == length, "unexpected frame length");
}
static void ipc_frame(int fd, unsigned char *body, size_t length, int writing, int64_t deadline) {
    unsigned char header[4]; prefix(header, length);
    io_exact(fd, header, 4, writing, deadline);
    if (!writing) check_prefix(header, length);
    io_exact(fd, body, length, writing, deadline);
}
static int ssl_retry(SSL *ssl, int result, int64_t deadline) {
    int error = SSL_get_error(ssl, result);
    if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
        ready(SSL_get_fd(ssl), error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
        return 1;
    }
    return 0;
}
static void handshake(SSL *ssl, int server, int64_t deadline) {
    for (;;) {
        require(millis() < deadline, "TLS handshake deadline");
        ERR_clear_error();
        int result = server ? SSL_accept(ssl) : SSL_connect(ssl);
        if (result == 1) return;
        require(ssl_retry(ssl, result, deadline), "TLS handshake");
    }
}
static void tls_exact(SSL *ssl, unsigned char *bytes, size_t length, int writing, int64_t deadline) {
    size_t done = 0;
    while (done < length) {
        require(millis() < deadline, "TLS frame deadline");
        size_t count = 0;
        ERR_clear_error();
        int result = writing ? SSL_write_ex(ssl, bytes + done, length - done, &count)
                             : SSL_read_ex(ssl, bytes + done, length - done, &count);
        if (result == 1) { require(count > 0, "zero TLS progress"); done += count; }
        else require(ssl_retry(ssl, result, deadline), "incomplete TLS frame");
    }
}
static void tls_frame(SSL *ssl, unsigned char *body, size_t length, int writing, int64_t deadline) {
    unsigned char header[4]; prefix(header, length);
    tls_exact(ssl, header, 4, writing, deadline);
    if (!writing) check_prefix(header, length);
    tls_exact(ssl, body, length, writing, deadline);
}
static void receive_end(SSL *ssl, int64_t deadline) {
    for (;;) {
        require(millis() < deadline, "TLS end deadline");
        unsigned char byte; size_t count = 0;
        ERR_clear_error();
        int result = SSL_read_ex(ssl, &byte, 1, &count);
        require(result != 1, "trailing TLS application bytes");
        if (SSL_get_error(ssl, result) == SSL_ERROR_ZERO_RETURN) return;
        require(ssl_retry(ssl, result, deadline), "missing authenticated TLS end");
    }
}
static void send_end(SSL *ssl, int64_t deadline) {
    for (;;) {
        require(millis() < deadline, "TLS shutdown deadline");
        ERR_clear_error();
        int result = SSL_shutdown(ssl);
        if (result == 1) return;
        /* Zero is the successful local half of SSL_shutdown, not an I/O
         * failure to classify with SSL_get_error. A pending alert write returns
         * a retry condition; SENT_SHUTDOWN alone does not prove its flush. */
        if (result == 0 && (SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN) && !SSL_want_write(ssl)) return;
        require(ssl_retry(ssl, result, deadline), "TLS shutdown");
    }
}
static unsigned char *read_file(const char *path, size_t *length, int secret) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    require(fd >= 0, "credential/configuration file");
    struct stat st;
    require(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size <= MAX_FILE,
            "credential/configuration size");
    require(!secret || (st.st_uid == geteuid() && (st.st_mode & 077) == 0), "private key permissions");
    *length = (size_t)st.st_size;
    unsigned char *bytes = OPENSSL_malloc(*length);
    require(bytes != NULL, "credential allocation");
    size_t done = 0;
    while (done < *length) {
        ssize_t count = read(fd, bytes + done, *length - done);
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "credential read"); done += (size_t)count;
    }
    unsigned char extra; require(read(fd, &extra, 1) == 0, "credential grew during read");
    require(close(fd) == 0, "credential close");
    return bytes;
}
static X509 *certificate(const char *path) {
    size_t size; unsigned char *bytes = read_file(path, &size, 0); const unsigned char *cursor = bytes;
    X509 *value = d2i_X509(NULL, &cursor, (long)size);
    int complete = value != NULL && cursor == bytes + size;
    OPENSSL_free(bytes); require(complete, "DER certificate"); return value;
}
static int same_certificate(X509 *left, X509 *right) {
    unsigned char *a = NULL, *b = NULL;
    int a_size = i2d_X509(left, &a), b_size = i2d_X509(right, &b);
    require(a_size > 0 && a_size <= MAX_FILE && b_size > 0 && b_size <= MAX_FILE, "peer DER encoding");
    int same = a_size == b_size && memcmp(a, b, (size_t)a_size) == 0;
    OPENSSL_free(a); OPENSSL_free(b); return same;
}
static SSL_CTX *context(const char *own, const char *key_path, struct binding *peers, size_t count) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method()); require(ctx != NULL, "TLS context");
    require(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1 &&
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1 &&
            SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768") == 1, "mandatory TLS group/version");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    require(SSL_CTX_set_num_tickets(ctx, 0) == 1 && SSL_CTX_set_max_early_data(ctx, 0) == 1,
            "disable tickets and early data");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    X509 *cert = certificate(own);
    require(SSL_CTX_use_certificate(ctx, cert) == 1, "own certificate"); X509_free(cert);
    size_t size; unsigned char *bytes = read_file(key_path, &size, 1); const unsigned char *cursor = bytes;
    EVP_PKEY *key = d2i_AutoPrivateKey(NULL, &cursor, (long)size);
    int complete = key != NULL && cursor == bytes + size;
    OPENSSL_clear_free(bytes, size); require(complete, "DER private key");
    int loaded = SSL_CTX_use_PrivateKey(ctx, key); EVP_PKEY_free(key);
    require(loaded == 1 && SSL_CTX_check_private_key(ctx) == 1, "certificate/key pair");
    for (size_t i = 0; i < count; ++i)
        require(X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), peers[i].certificate) == 1, "peer trust anchor");
    return ctx;
}
static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *length,
                       const unsigned char *in, unsigned int size, void *argument) {
    (void)ssl; (void)argument;
    while (size > 0) {
        unsigned int item = in[0]; ++in; --size;
        if (!item || item > size) return SSL_TLSEXT_ERR_ALERT_FATAL;
        if (item == sizeof(protocol)-1 && memcmp(in, protocol, item) == 0) {
            *out = protocol; *length = (unsigned char)item; return SSL_TLSEXT_ERR_OK;
        }
        in += item; size -= item;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}
static X509 *negotiated(SSL *ssl) {
    unsigned int size = 0; const unsigned char *alpn = NULL;
    SSL_get0_alpn_selected(ssl, &alpn, &size);
    long group = SSL_get_negotiated_group(ssl);
    require(group > 0 && group <= INT_MAX, "negotiated group identifier");
    const char *name = SSL_group_to_name(ssl, (int)group);
    require(SSL_version(ssl) == TLS1_3_VERSION && name && strcmp(name, "X25519MLKEM768") == 0 &&
            !SSL_session_reused(ssl) && size == sizeof(protocol)-1 &&
            memcmp(alpn, protocol, size) == 0 && SSL_get_verify_result(ssl) == X509_V_OK,
            "negotiated TLS contract");
    X509 *peer = SSL_get1_peer_certificate(ssl); require(peer != NULL, "mutual certificate");
    return peer;
}
static int socket_for(const char *address, int server) {
    struct sockaddr_in endpoint = { .sin_family = AF_INET };
    const char *port = strchr(address, ':'); require(port != NULL && port-address < 16, "numeric endpoint");
    char ip[16]; memcpy(ip, address, (size_t)(port-address)); ip[port-address] = 0;
    char *end = NULL; errno = 0; unsigned long number = strtoul(port+1, &end, 10);
    require(!errno && end != port+1 && *end == 0 && number <= 65535 && (server || number != 0) &&
            inet_pton(AF_INET, ip, &endpoint.sin_addr) == 1 && endpoint.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
            "reference peer requires an explicit loopback endpoint");
    endpoint.sin_port = htons((uint16_t)number);
    int fd = socket(AF_INET, SOCK_STREAM, 0); require(fd >= 0, "TCP socket"); nonblock(fd);
    if (server) {
        require(bind(fd, (struct sockaddr *)&endpoint, sizeof(endpoint)) == 0 && listen(fd, 8) == 0, "listener");
        socklen_t size = sizeof(endpoint); require(getsockname(fd, (struct sockaddr *)&endpoint, &size) == 0, "listener port");
        require(printf("LISTEN 127.0.0.1:%u\n", (unsigned)ntohs(endpoint.sin_port)) > 0 && fflush(stdout) == 0,
                "listener announcement");
    } else {
        int result = connect(fd, (struct sockaddr *)&endpoint, sizeof(endpoint));
        require(result == 0 || errno == EINPROGRESS, "connect");
        if (result != 0) {
            ready(fd, POLLOUT, millis()+5000); int error = 0; socklen_t size = sizeof(error);
            require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0, "connected socket");
        }
    }
    return fd;
}
int main(int argc, char **argv) {
    require(signal(SIGPIPE, SIG_IGN) != SIG_ERR, "SIGPIPE handling");
    /* This isolated reference process uses the linked default provider, with
     * no inherited application/provider configuration or external trust file. */
    require(OPENSSL_init_ssl(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) == 1, "OpenSSL initialization");
    require(argc >= 2, "mode");
    if (argc == 2 && strcmp(argv[1], "identity") == 0) {
        require(printf("OPENSSL_HEADER %s\nOPENSSL_RUNTIME %s\n", OPENSSL_VERSION_TEXT,
                       OpenSSL_version(OPENSSL_VERSION)) > 0 && fflush(stdout) == 0, "library identity");
        return 0;
    }
    int server = strcmp(argv[1], "server") == 0;
    require((server && argc == 9) || (!server && strcmp(argv[1], "client") == 0 && argc == 7), "arguments");
    struct binding peers[2] = {0}; size_t count = server ? 2 : 1;
    peers[0].certificate = certificate(argv[5]);
    if (server) {
        peers[1].certificate = certificate(argv[7]);
        for (size_t i = 0; i < count; ++i) {
            size_t size; unsigned char *subject = read_file(argv[6+i*2], &size, 0);
            require(size == SUBJECT, "trusted subject width"); memcpy(peers[i].subject, subject, SUBJECT); OPENSSL_free(subject);
        }
    }
    SSL_CTX *ctx = context(argv[3], argv[4], peers, count);
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    nonblock(STDIN_FILENO); nonblock(STDOUT_FILENO);
    int listener = server ? socket_for(argv[2], 1) : -1;
    unsigned int exchanges = 0;
    for (;;) {
        int fd;
        if (server) {
            struct pollfd fds[2] = {{.fd=listener,.events=POLLIN}, {.fd=STDIN_FILENO,.events=POLLIN}};
            int result = poll(fds, 2, 1000);
            if (result < 0 && errno == EINTR) continue;
            require(result >= 0, "listener readiness");
            require(!(fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)), "listener state");
            if (fds[1].revents & POLLHUP) break;
            require(!(fds[1].revents & (POLLIN | POLLERR | POLLNVAL)), "unexpected idle host input");
            if (!(fds[0].revents & POLLIN)) continue;
            fd = accept(listener, NULL, NULL); require(fd >= 0, "accept"); nonblock(fd);
        } else fd = socket_for(argv[2], 0);
        require(exchanges < 1024, "reference exchange capacity");
        int64_t deadline = millis()+5000;
        SSL *ssl = SSL_new(ctx); require(ssl != NULL && SSL_set_fd(ssl, fd) == 1, "TLS socket");
        if (!server) {
            unsigned char offered[sizeof(protocol)]; offered[0] = (unsigned char)(sizeof(protocol)-1);
            memcpy(offered+1, protocol, sizeof(protocol)-1);
            require(SSL_set_alpn_protos(ssl, offered, sizeof(offered)) == 0 &&
                    SSL_set1_host(ssl, argv[6]) == 1 && SSL_set_tlsext_host_name(ssl, argv[6]) == 1, "client name/ALPN");
        }
        handshake(ssl, server, deadline); X509 *peer = negotiated(ssl);
        unsigned char request[REQUEST], reply[REPLY];
        if (server) {
            tls_frame(ssl, request, REQUEST, 0, deadline); receive_end(ssl, deadline);
            int authorized = 0;
            for (size_t i = 0; i < count; ++i)
                if (same_certificate(peer, peers[i].certificate) && memcmp(request+44, peers[i].subject, SUBJECT) == 0) authorized = 1;
            require(authorized && memcmp(request+4, "QPANRQ01", 8) == 0, "certificate/subject admission");
            ipc_frame(STDOUT_FILENO, request, REQUEST, 1, deadline);
            ipc_frame(STDIN_FILENO, reply, REPLY, 0, deadline);
            tls_frame(ssl, reply, REPLY, 1, deadline); send_end(ssl, deadline);
        } else {
            require(same_certificate(peer, peers[0].certificate), "server leaf pin");
            ipc_frame(STDIN_FILENO, request, REQUEST, 0, deadline);
            tls_frame(ssl, request, REQUEST, 1, deadline); send_end(ssl, deadline);
            tls_frame(ssl, reply, REPLY, 0, deadline); receive_end(ssl, deadline);
            ipc_frame(STDOUT_FILENO, reply, REPLY, 1, deadline);
        }
        require((SSL_get_shutdown(ssl) & (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) ==
                (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN), "complete authenticated shutdown");
        X509_free(peer); SSL_free(ssl); require(close(fd) == 0, "connection close");
        ++exchanges; require(exchanges <= 1024, "reference exchange capacity");
        require(fprintf(stderr, "OPENSSL_WITNESS_OK role=%s tls=1.3 group=X25519MLKEM768 alpn=q-periapt-anchor/1 exchange=%u\n",
                        server ? "server" : "client", exchanges) > 0 && fflush(stderr) == 0, "public result");
        if (!server) break;
    }
    if (listener >= 0) require(close(listener) == 0, "listener close");
    for (size_t i = 0; i < count; ++i) X509_free(peers[i].certificate);
    SSL_CTX_free(ctx); return 0;
}
