/* Constant-time verification shim for the `valgrind` feature.
 *
 * When built with -DHAVE_VALGRIND (i.e. <valgrind/memcheck.h> is available, as on a
 * Linux CI runner with Valgrind installed), `qperiapt_ct_mark_undefined` issues the
 * Memcheck MAKE_MEM_UNDEFINED client request, marking the bytes "secret" so Memcheck
 * flags any later branch/index that depends on them. Without the header it is a
 * no-op for feature-disabled builds. Feature-enabled builds fail in build.rs when
 * the real header is absent, so a purported CT harness cannot silently do nothing. */

#include <stddef.h>

#ifdef HAVE_VALGRIND
#include <valgrind/memcheck.h>
void qperiapt_ct_mark_undefined(void *p, size_t n) {
    (void) VALGRIND_MAKE_MEM_UNDEFINED(p, n);
}
#else
void qperiapt_ct_mark_undefined(void *p, size_t n) {
    (void) p;
    (void) n;
}
#endif
