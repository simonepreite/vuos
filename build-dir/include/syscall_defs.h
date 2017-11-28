#ifndef __VU_SYSCALL_DEFS__
#define __VU_SYSCALL_DEFS__

/* Arch independent definitions */

#define __VU_null 0
#define __VU_open 1
#define __VU_close 2
#define __VU_read 3
#define __VU_write 4
#define __VU_pread64 5
#define __VU_pwrite64 6
#define __VU_getdents64 7
#define __VU_fcntl 8
#define __VU_lseek 9
#define __VU_lstat 10
#define __VU_access 11
#define __VU_readlink 12
#define __VU_unlink 13
#define __VU_truncate 14
#define __VU_mkdir 15
#define __VU_rmdir 16
#define __VU_mknod 17
#define __VU_lchown 18
#define __VU_chmod 19
#define __VU_utimensat 20
#define __VU_link 21
#define __VU_symlink 22
#define __VU_rename 23
#define __VU_mount 24
#define __VU_umount2 25
#define __VU_lgetxattr 26
#define __VU_lsetxattr 27
#define __VU_llistxattr 28
#define __VU_lremovexattr 29
#define __VU_ioctl 30
#define __VU_epoll_ctl 31
#define __VU_setresfuid 32
#define __VU_setresfgid 33
#define __VU_getresfuid 34
#define __VU_getresfgid 35
#define __VU_setgroups 36
#define __VU_getgroups 37
#define __VU_msocket 38
#define __VU_bind 39
#define __VU_connect 40
#define __VU_listen 41
#define __VU_accept4 42
#define __VU_getsockname 43
#define __VU_getpeername 44
#define __VU_sendto 45
#define __VU_recvfrom 46
#define __VU_shutdown 47
#define __VU_setsockopt 48
#define __VU_getsockopt 49
#define __VU_execve 50
#define __VU_dup3 51
#define __VU_chdir 52
#define __VU_getcwd 53
#define __VU_umask 54
#define __VU_chroot 55
#define __VU_mmap 56
#define __VU_munmap 57
#define __VU_mremap 58
#define __VU_msync 59
#define __VU_epoll_create1 60
#define __VU_epoll_wait 61
#define __VU_poll 62
#define __VU_select 63
#define __VU_sendfile 64
#define __VVU_insmod -1
#define __VVU_rmmod -2
#define __VVU_lsmod -3
#define __VVU_vuctl -4
#define __VVU_msocket -5

#define VU_NR_SYSCALLS 65
#define VU_NR_MODULE_SYSCALLS 50
#define VVU_NR_SYSCALLS 6
#define VU_SYSCALL_MAX_NAMELEN 13
#define VVU_SYSCALL_MAX_NAMELEN 7

#endif
