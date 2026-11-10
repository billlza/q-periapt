/* SPDX-License-Identifier: Apache-2.0 OR MIT */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1
#include <fcntl.h>
#include <unistd.h>
static int sync_file(int fd) {
#if defined(__APPLE__)
 return fcntl(fd,F_FULLFSYNC);
#else
 return fdatasync(fd);
#endif
}
int main(int argc,char **argv) {
 if(argc!=3)return 1;
 int a=open(argv[1],O_RDWR|O_CLOEXEC),b=open(argv[2],O_RDWR|O_CLOEXEC);
 if(a<0||b<0)return 2;
 int flags=fcntl(a,F_GETFD);if(flags<0||fcntl(a,F_SETFD,flags|FD_CLOEXEC))return 3;
 if(write(b,"control",7)!=7||sync_file(b))return 4;
 if(write(a,"one",3)!=3||sync_file(a))return 5;
 if(write(a,"two",3)!=3||sync_file(a))return 6;
 if(close(a)||close(b))return 7;
 return 0;
}
