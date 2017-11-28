#ifndef R_TABLE_H
#define R_TABLE_H

#include <unistd.h>
#include <sys/syscall.h>

extern long (*native_syscall)();

#define r__Exit(...) native_syscall(__NR__Exit, ## __VA_ARGS__)
#define r___clone2(...) native_syscall(__NR___clone2, ## __VA_ARGS__)
#define r__exit(...) native_syscall(__NR__exit, ## __VA_ARGS__)
#define r__llseek(...) native_syscall(__NR__llseek, ## __VA_ARGS__)
#define r__newselect(...) native_syscall(__NR__newselect, ## __VA_ARGS__)
#define r__syscall(...) native_syscall(__NR__syscall, ## __VA_ARGS__)
#define r__sysctl(...) native_syscall(__NR__sysctl, ## __VA_ARGS__)
#define r_accept(...) native_syscall(__NR_accept, ## __VA_ARGS__)
#define r_accept4(...) native_syscall(__NR_accept4, ## __VA_ARGS__)
#define r_access(...) native_syscall(__NR_access, ## __VA_ARGS__)
#define r_acct(...) native_syscall(__NR_acct, ## __VA_ARGS__)
#define r_add_key(...) native_syscall(__NR_add_key, ## __VA_ARGS__)
#define r_adjtimex(...) native_syscall(__NR_adjtimex, ## __VA_ARGS__)
#define r_afs_syscall(...) native_syscall(__NR_afs_syscall, ## __VA_ARGS__)
#define r_alarm(...) native_syscall(__NR_alarm, ## __VA_ARGS__)
#define r_alloc_hugepages(...) native_syscall(__NR_alloc_hugepages, ## __VA_ARGS__)
#define r_arch_prctl(...) native_syscall(__NR_arch_prctl, ## __VA_ARGS__)
#define r_arm_fadvise(...) native_syscall(__NR_arm_fadvise, ## __VA_ARGS__)
#define r_arm_fadvise64_64(...) native_syscall(__NR_arm_fadvise64_64, ## __VA_ARGS__)
#define r_arm_sync_file_range(...) native_syscall(__NR_arm_sync_file_range, ## __VA_ARGS__)
#define r_bdflush(...) native_syscall(__NR_bdflush, ## __VA_ARGS__)
#define r_bind(...) native_syscall(__NR_bind, ## __VA_ARGS__)
#define r_bpf(...) native_syscall(__NR_bpf, ## __VA_ARGS__)
#define r_break(...) native_syscall(__NR_break, ## __VA_ARGS__)
#define r_brk(...) native_syscall(__NR_brk, ## __VA_ARGS__)
#define r_cacheflush(...) native_syscall(__NR_cacheflush, ## __VA_ARGS__)
#define r_capget(...) native_syscall(__NR_capget, ## __VA_ARGS__)
#define r_capset(...) native_syscall(__NR_capset, ## __VA_ARGS__)
#define r_chdir(...) native_syscall(__NR_chdir, ## __VA_ARGS__)
#define r_chmod(...) native_syscall(__NR_chmod, ## __VA_ARGS__)
#define r_chown(...) native_syscall(__NR_chown, ## __VA_ARGS__)
#define r_chown32(...) native_syscall(__NR_chown32, ## __VA_ARGS__)
#define r_chroot(...) native_syscall(__NR_chroot, ## __VA_ARGS__)
#define r_clock_getres(...) native_syscall(__NR_clock_getres, ## __VA_ARGS__)
#define r_clock_gettime(...) native_syscall(__NR_clock_gettime, ## __VA_ARGS__)
#define r_clock_nanosleep(...) native_syscall(__NR_clock_nanosleep, ## __VA_ARGS__)
#define r_clock_settime(...) native_syscall(__NR_clock_settime, ## __VA_ARGS__)
#define r_clone(...) native_syscall(__NR_clone, ## __VA_ARGS__)
#define r_clone2(...) native_syscall(__NR_clone2, ## __VA_ARGS__)
#define r_close(...) native_syscall(__NR_close, ## __VA_ARGS__)
#define r_connect(...) native_syscall(__NR_connect, ## __VA_ARGS__)
#define r_copy_file_range(...) native_syscall(__NR_copy_file_range, ## __VA_ARGS__)
#define r_creat(...) native_syscall(__NR_creat, ## __VA_ARGS__)
#define r_create_module(...) native_syscall(__NR_create_module, ## __VA_ARGS__)
#define r_delete_module(...) native_syscall(__NR_delete_module, ## __VA_ARGS__)
#define r_dup(...) native_syscall(__NR_dup, ## __VA_ARGS__)
#define r_dup2(...) native_syscall(__NR_dup2, ## __VA_ARGS__)
#define r_dup3(...) native_syscall(__NR_dup3, ## __VA_ARGS__)
#define r_epoll_create(...) native_syscall(__NR_epoll_create, ## __VA_ARGS__)
#define r_epoll_create1(...) native_syscall(__NR_epoll_create1, ## __VA_ARGS__)
#define r_epoll_ctl(...) native_syscall(__NR_epoll_ctl, ## __VA_ARGS__)
#define r_epoll_pwait(...) native_syscall(__NR_epoll_pwait, ## __VA_ARGS__)
#define r_epoll_wait(...) native_syscall(__NR_epoll_wait, ## __VA_ARGS__)
#define r_eventfd(...) native_syscall(__NR_eventfd, ## __VA_ARGS__)
#define r_eventfd2(...) native_syscall(__NR_eventfd2, ## __VA_ARGS__)
#define r_execve(...) native_syscall(__NR_execve, ## __VA_ARGS__)
#define r_execveat(...) native_syscall(__NR_execveat, ## __VA_ARGS__)
#define r_exit(...) native_syscall(__NR_exit, ## __VA_ARGS__)
#define r_exit_group(...) native_syscall(__NR_exit_group, ## __VA_ARGS__)
#define r_faccessat(...) native_syscall(__NR_faccessat, ## __VA_ARGS__)
#define r_fadvise64(...) native_syscall(__NR_fadvise64, ## __VA_ARGS__)
#define r_fadvise64_64(...) native_syscall(__NR_fadvise64_64, ## __VA_ARGS__)
#define r_fallocate(...) native_syscall(__NR_fallocate, ## __VA_ARGS__)
#define r_fanotify_init(...) native_syscall(__NR_fanotify_init, ## __VA_ARGS__)
#define r_fanotify_mark(...) native_syscall(__NR_fanotify_mark, ## __VA_ARGS__)
#define r_fattach(...) native_syscall(__NR_fattach, ## __VA_ARGS__)
#define r_fchdir(...) native_syscall(__NR_fchdir, ## __VA_ARGS__)
#define r_fchmod(...) native_syscall(__NR_fchmod, ## __VA_ARGS__)
#define r_fchmodat(...) native_syscall(__NR_fchmodat, ## __VA_ARGS__)
#define r_fchown(...) native_syscall(__NR_fchown, ## __VA_ARGS__)
#define r_fchown32(...) native_syscall(__NR_fchown32, ## __VA_ARGS__)
#define r_fchownat(...) native_syscall(__NR_fchownat, ## __VA_ARGS__)
#define r_fcntl(...) native_syscall(__NR_fcntl, ## __VA_ARGS__)
#define r_fcntl64(...) native_syscall(__NR_fcntl64, ## __VA_ARGS__)
#define r_fdatasync(...) native_syscall(__NR_fdatasync, ## __VA_ARGS__)
#define r_fdetach(...) native_syscall(__NR_fdetach, ## __VA_ARGS__)
#define r_fgetxattr(...) native_syscall(__NR_fgetxattr, ## __VA_ARGS__)
#define r_finit_module(...) native_syscall(__NR_finit_module, ## __VA_ARGS__)
#define r_flistxattr(...) native_syscall(__NR_flistxattr, ## __VA_ARGS__)
#define r_flock(...) native_syscall(__NR_flock, ## __VA_ARGS__)
#define r_fork(...) native_syscall(__NR_fork, ## __VA_ARGS__)
#define r_free_hugepages(...) native_syscall(__NR_free_hugepages, ## __VA_ARGS__)
#define r_fremovexattr(...) native_syscall(__NR_fremovexattr, ## __VA_ARGS__)
#define r_fsetxattr(...) native_syscall(__NR_fsetxattr, ## __VA_ARGS__)
#define r_fstat(...) native_syscall(__NR_fstat, ## __VA_ARGS__)
#define r_fstat64(...) native_syscall(__NR_fstat64, ## __VA_ARGS__)
#define r_fstatat(...) native_syscall(__NR_fstatat, ## __VA_ARGS__)
#define r_fstatat64(...) native_syscall(__NR_fstatat64, ## __VA_ARGS__)
#define r_fstatfs(...) native_syscall(__NR_fstatfs, ## __VA_ARGS__)
#define r_fstatfs64(...) native_syscall(__NR_fstatfs64, ## __VA_ARGS__)
#define r_fstatvfs(...) native_syscall(__NR_fstatvfs, ## __VA_ARGS__)
#define r_fsync(...) native_syscall(__NR_fsync, ## __VA_ARGS__)
#define r_ftruncate(...) native_syscall(__NR_ftruncate, ## __VA_ARGS__)
#define r_ftruncate64(...) native_syscall(__NR_ftruncate64, ## __VA_ARGS__)
#define r_futex(...) native_syscall(__NR_futex, ## __VA_ARGS__)
#define r_futimesat(...) native_syscall(__NR_futimesat, ## __VA_ARGS__)
#define r_get_kernel_syms(...) native_syscall(__NR_get_kernel_syms, ## __VA_ARGS__)
#define r_get_mempolicy(...) native_syscall(__NR_get_mempolicy, ## __VA_ARGS__)
#define r_get_robust_list(...) native_syscall(__NR_get_robust_list, ## __VA_ARGS__)
#define r_get_thread_area(...) native_syscall(__NR_get_thread_area, ## __VA_ARGS__)
#define r_getcontext(...) native_syscall(__NR_getcontext, ## __VA_ARGS__)
#define r_getcpu(...) native_syscall(__NR_getcpu, ## __VA_ARGS__)
#define r_getcwd(...) native_syscall(__NR_getcwd, ## __VA_ARGS__)
#define r_getdents(...) native_syscall(__NR_getdents, ## __VA_ARGS__)
#define r_getdents64(...) native_syscall(__NR_getdents64, ## __VA_ARGS__)
#define r_getdomainname(...) native_syscall(__NR_getdomainname, ## __VA_ARGS__)
#define r_getdtablesize(...) native_syscall(__NR_getdtablesize, ## __VA_ARGS__)
#define r_getegid(...) native_syscall(__NR_getegid, ## __VA_ARGS__)
#define r_getegid32(...) native_syscall(__NR_getegid32, ## __VA_ARGS__)
#define r_geteuid(...) native_syscall(__NR_geteuid, ## __VA_ARGS__)
#define r_geteuid32(...) native_syscall(__NR_geteuid32, ## __VA_ARGS__)
#define r_getgid(...) native_syscall(__NR_getgid, ## __VA_ARGS__)
#define r_getgid32(...) native_syscall(__NR_getgid32, ## __VA_ARGS__)
#define r_getgroups(...) native_syscall(__NR_getgroups, ## __VA_ARGS__)
#define r_getgroups32(...) native_syscall(__NR_getgroups32, ## __VA_ARGS__)
#define r_gethostid(...) native_syscall(__NR_gethostid, ## __VA_ARGS__)
#define r_gethostname(...) native_syscall(__NR_gethostname, ## __VA_ARGS__)
#define r_getitimer(...) native_syscall(__NR_getitimer, ## __VA_ARGS__)
#define r_getmsg(...) native_syscall(__NR_getmsg, ## __VA_ARGS__)
#define r_getpagesize(...) native_syscall(__NR_getpagesize, ## __VA_ARGS__)
#define r_getpeername(...) native_syscall(__NR_getpeername, ## __VA_ARGS__)
#define r_getpgid(...) native_syscall(__NR_getpgid, ## __VA_ARGS__)
#define r_getpgrp(...) native_syscall(__NR_getpgrp, ## __VA_ARGS__)
#define r_getpid(...) native_syscall(__NR_getpid, ## __VA_ARGS__)
#define r_getpmsg(...) native_syscall(__NR_getpmsg, ## __VA_ARGS__)
#define r_getppid(...) native_syscall(__NR_getppid, ## __VA_ARGS__)
#define r_getpriority(...) native_syscall(__NR_getpriority, ## __VA_ARGS__)
#define r_getrandom(...) native_syscall(__NR_getrandom, ## __VA_ARGS__)
#define r_getresgid(...) native_syscall(__NR_getresgid, ## __VA_ARGS__)
#define r_getresgid32(...) native_syscall(__NR_getresgid32, ## __VA_ARGS__)
#define r_getresuid(...) native_syscall(__NR_getresuid, ## __VA_ARGS__)
#define r_getresuid32(...) native_syscall(__NR_getresuid32, ## __VA_ARGS__)
#define r_getrlimit(...) native_syscall(__NR_getrlimit, ## __VA_ARGS__)
#define r_getrusage(...) native_syscall(__NR_getrusage, ## __VA_ARGS__)
#define r_getsid(...) native_syscall(__NR_getsid, ## __VA_ARGS__)
#define r_getsockname(...) native_syscall(__NR_getsockname, ## __VA_ARGS__)
#define r_getsockopt(...) native_syscall(__NR_getsockopt, ## __VA_ARGS__)
#define r_gettid(...) native_syscall(__NR_gettid, ## __VA_ARGS__)
#define r_gettimeofday(...) native_syscall(__NR_gettimeofday, ## __VA_ARGS__)
#define r_getuid(...) native_syscall(__NR_getuid, ## __VA_ARGS__)
#define r_getuid32(...) native_syscall(__NR_getuid32, ## __VA_ARGS__)
#define r_getunwind(...) native_syscall(__NR_getunwind, ## __VA_ARGS__)
#define r_getxattr(...) native_syscall(__NR_getxattr, ## __VA_ARGS__)
#define r_gtty(...) native_syscall(__NR_gtty, ## __VA_ARGS__)
#define r_idle(...) native_syscall(__NR_idle, ## __VA_ARGS__)
#define r_inb(...) native_syscall(__NR_inb, ## __VA_ARGS__)
#define r_inb_p(...) native_syscall(__NR_inb_p, ## __VA_ARGS__)
#define r_init_module(...) native_syscall(__NR_init_module, ## __VA_ARGS__)
#define r_inl(...) native_syscall(__NR_inl, ## __VA_ARGS__)
#define r_inl_p(...) native_syscall(__NR_inl_p, ## __VA_ARGS__)
#define r_inotify_add_watch(...) native_syscall(__NR_inotify_add_watch, ## __VA_ARGS__)
#define r_inotify_init(...) native_syscall(__NR_inotify_init, ## __VA_ARGS__)
#define r_inotify_init1(...) native_syscall(__NR_inotify_init1, ## __VA_ARGS__)
#define r_inotify_rm_watch(...) native_syscall(__NR_inotify_rm_watch, ## __VA_ARGS__)
#define r_insb(...) native_syscall(__NR_insb, ## __VA_ARGS__)
#define r_insl(...) native_syscall(__NR_insl, ## __VA_ARGS__)
#define r_insw(...) native_syscall(__NR_insw, ## __VA_ARGS__)
#define r_intro(...) native_syscall(__NR_intro, ## __VA_ARGS__)
#define r_inw(...) native_syscall(__NR_inw, ## __VA_ARGS__)
#define r_inw_p(...) native_syscall(__NR_inw_p, ## __VA_ARGS__)
#define r_io_cancel(...) native_syscall(__NR_io_cancel, ## __VA_ARGS__)
#define r_io_destroy(...) native_syscall(__NR_io_destroy, ## __VA_ARGS__)
#define r_io_getevents(...) native_syscall(__NR_io_getevents, ## __VA_ARGS__)
#define r_io_setup(...) native_syscall(__NR_io_setup, ## __VA_ARGS__)
#define r_io_submit(...) native_syscall(__NR_io_submit, ## __VA_ARGS__)
#define r_ioctl(...) native_syscall(__NR_ioctl, ## __VA_ARGS__)
#define r_ioctl_console(...) native_syscall(__NR_ioctl_console, ## __VA_ARGS__)
#define r_ioctl_fat(...) native_syscall(__NR_ioctl_fat, ## __VA_ARGS__)
#define r_ioctl_ficlone(...) native_syscall(__NR_ioctl_ficlone, ## __VA_ARGS__)
#define r_ioctl_ficlonerange(...) native_syscall(__NR_ioctl_ficlonerange, ## __VA_ARGS__)
#define r_ioctl_fideduperange(...) native_syscall(__NR_ioctl_fideduperange, ## __VA_ARGS__)
#define r_ioctl_getfsmap(...) native_syscall(__NR_ioctl_getfsmap, ## __VA_ARGS__)
#define r_ioctl_iflags(...) native_syscall(__NR_ioctl_iflags, ## __VA_ARGS__)
#define r_ioctl_list(...) native_syscall(__NR_ioctl_list, ## __VA_ARGS__)
#define r_ioctl_ns(...) native_syscall(__NR_ioctl_ns, ## __VA_ARGS__)
#define r_ioctl_tty(...) native_syscall(__NR_ioctl_tty, ## __VA_ARGS__)
#define r_ioctl_userfaultfd(...) native_syscall(__NR_ioctl_userfaultfd, ## __VA_ARGS__)
#define r_ioperm(...) native_syscall(__NR_ioperm, ## __VA_ARGS__)
#define r_iopl(...) native_syscall(__NR_iopl, ## __VA_ARGS__)
#define r_ioprio_get(...) native_syscall(__NR_ioprio_get, ## __VA_ARGS__)
#define r_ioprio_set(...) native_syscall(__NR_ioprio_set, ## __VA_ARGS__)
#define r_ipc(...) native_syscall(__NR_ipc, ## __VA_ARGS__)
#define r_isastream(...) native_syscall(__NR_isastream, ## __VA_ARGS__)
#define r_kcmp(...) native_syscall(__NR_kcmp, ## __VA_ARGS__)
#define r_kexec_file_load(...) native_syscall(__NR_kexec_file_load, ## __VA_ARGS__)
#define r_kexec_load(...) native_syscall(__NR_kexec_load, ## __VA_ARGS__)
#define r_keyctl(...) native_syscall(__NR_keyctl, ## __VA_ARGS__)
#define r_kill(...) native_syscall(__NR_kill, ## __VA_ARGS__)
#define r_killpg(...) native_syscall(__NR_killpg, ## __VA_ARGS__)
#define r_lchown(...) native_syscall(__NR_lchown, ## __VA_ARGS__)
#define r_lchown32(...) native_syscall(__NR_lchown32, ## __VA_ARGS__)
#define r_lgetxattr(...) native_syscall(__NR_lgetxattr, ## __VA_ARGS__)
#define r_link(...) native_syscall(__NR_link, ## __VA_ARGS__)
#define r_linkat(...) native_syscall(__NR_linkat, ## __VA_ARGS__)
#define r_listen(...) native_syscall(__NR_listen, ## __VA_ARGS__)
#define r_listxattr(...) native_syscall(__NR_listxattr, ## __VA_ARGS__)
#define r_llistxattr(...) native_syscall(__NR_llistxattr, ## __VA_ARGS__)
#define r_llseek(...) native_syscall(__NR_llseek, ## __VA_ARGS__)
#define r_lock(...) native_syscall(__NR_lock, ## __VA_ARGS__)
#define r_lookup_dcookie(...) native_syscall(__NR_lookup_dcookie, ## __VA_ARGS__)
#define r_lremovexattr(...) native_syscall(__NR_lremovexattr, ## __VA_ARGS__)
#define r_lseek(...) native_syscall(__NR_lseek, ## __VA_ARGS__)
#define r_lsetxattr(...) native_syscall(__NR_lsetxattr, ## __VA_ARGS__)
#define r_lstat(...) native_syscall(__NR_lstat, ## __VA_ARGS__)
#define r_lstat64(...) native_syscall(__NR_lstat64, ## __VA_ARGS__)
#define r_madvise(...) native_syscall(__NR_madvise, ## __VA_ARGS__)
#define r_madvise1(...) native_syscall(__NR_madvise1, ## __VA_ARGS__)
#define r_mbind(...) native_syscall(__NR_mbind, ## __VA_ARGS__)
#define r_membarrier(...) native_syscall(__NR_membarrier, ## __VA_ARGS__)
#define r_memfd_create(...) native_syscall(__NR_memfd_create, ## __VA_ARGS__)
#define r_migrate_pages(...) native_syscall(__NR_migrate_pages, ## __VA_ARGS__)
#define r_mincore(...) native_syscall(__NR_mincore, ## __VA_ARGS__)
#define r_mkdir(...) native_syscall(__NR_mkdir, ## __VA_ARGS__)
#define r_mkdirat(...) native_syscall(__NR_mkdirat, ## __VA_ARGS__)
#define r_mknod(...) native_syscall(__NR_mknod, ## __VA_ARGS__)
#define r_mknodat(...) native_syscall(__NR_mknodat, ## __VA_ARGS__)
#define r_mlock(...) native_syscall(__NR_mlock, ## __VA_ARGS__)
#define r_mlock2(...) native_syscall(__NR_mlock2, ## __VA_ARGS__)
#define r_mlockall(...) native_syscall(__NR_mlockall, ## __VA_ARGS__)
#define r_mmap(...) native_syscall(__NR_mmap, ## __VA_ARGS__)
#define r_mmap2(...) native_syscall(__NR_mmap2, ## __VA_ARGS__)
#define r_modify_ldt(...) native_syscall(__NR_modify_ldt, ## __VA_ARGS__)
#define r_mount(...) native_syscall(__NR_mount, ## __VA_ARGS__)
#define r_move_pages(...) native_syscall(__NR_move_pages, ## __VA_ARGS__)
#define r_mprotect(...) native_syscall(__NR_mprotect, ## __VA_ARGS__)
#define r_mpx(...) native_syscall(__NR_mpx, ## __VA_ARGS__)
#define r_mq_getsetattr(...) native_syscall(__NR_mq_getsetattr, ## __VA_ARGS__)
#define r_mq_notify(...) native_syscall(__NR_mq_notify, ## __VA_ARGS__)
#define r_mq_open(...) native_syscall(__NR_mq_open, ## __VA_ARGS__)
#define r_mq_timedreceive(...) native_syscall(__NR_mq_timedreceive, ## __VA_ARGS__)
#define r_mq_timedsend(...) native_syscall(__NR_mq_timedsend, ## __VA_ARGS__)
#define r_mq_unlink(...) native_syscall(__NR_mq_unlink, ## __VA_ARGS__)
#define r_mremap(...) native_syscall(__NR_mremap, ## __VA_ARGS__)
#define r_msgctl(...) native_syscall(__NR_msgctl, ## __VA_ARGS__)
#define r_msgget(...) native_syscall(__NR_msgget, ## __VA_ARGS__)
#define r_msgop(...) native_syscall(__NR_msgop, ## __VA_ARGS__)
#define r_msgrcv(...) native_syscall(__NR_msgrcv, ## __VA_ARGS__)
#define r_msgsnd(...) native_syscall(__NR_msgsnd, ## __VA_ARGS__)
#define r_msync(...) native_syscall(__NR_msync, ## __VA_ARGS__)
#define r_munlock(...) native_syscall(__NR_munlock, ## __VA_ARGS__)
#define r_munlockall(...) native_syscall(__NR_munlockall, ## __VA_ARGS__)
#define r_munmap(...) native_syscall(__NR_munmap, ## __VA_ARGS__)
#define r_name_to_handle_at(...) native_syscall(__NR_name_to_handle_at, ## __VA_ARGS__)
#define r_nanosleep(...) native_syscall(__NR_nanosleep, ## __VA_ARGS__)
#define r_newfstatat(...) native_syscall(__NR_newfstatat, ## __VA_ARGS__)
#define r_nfsservctl(...) native_syscall(__NR_nfsservctl, ## __VA_ARGS__)
#define r_nice(...) native_syscall(__NR_nice, ## __VA_ARGS__)
#define r_oldfstat(...) native_syscall(__NR_oldfstat, ## __VA_ARGS__)
#define r_oldlstat(...) native_syscall(__NR_oldlstat, ## __VA_ARGS__)
#define r_oldolduname(...) native_syscall(__NR_oldolduname, ## __VA_ARGS__)
#define r_oldstat(...) native_syscall(__NR_oldstat, ## __VA_ARGS__)
#define r_olduname(...) native_syscall(__NR_olduname, ## __VA_ARGS__)
#define r_open(...) native_syscall(__NR_open, ## __VA_ARGS__)
#define r_open_by_handle_at(...) native_syscall(__NR_open_by_handle_at, ## __VA_ARGS__)
#define r_openat(...) native_syscall(__NR_openat, ## __VA_ARGS__)
#define r_outb(...) native_syscall(__NR_outb, ## __VA_ARGS__)
#define r_outb_p(...) native_syscall(__NR_outb_p, ## __VA_ARGS__)
#define r_outl(...) native_syscall(__NR_outl, ## __VA_ARGS__)
#define r_outl_p(...) native_syscall(__NR_outl_p, ## __VA_ARGS__)
#define r_outsb(...) native_syscall(__NR_outsb, ## __VA_ARGS__)
#define r_outsl(...) native_syscall(__NR_outsl, ## __VA_ARGS__)
#define r_outsw(...) native_syscall(__NR_outsw, ## __VA_ARGS__)
#define r_outw(...) native_syscall(__NR_outw, ## __VA_ARGS__)
#define r_outw_p(...) native_syscall(__NR_outw_p, ## __VA_ARGS__)
#define r_pause(...) native_syscall(__NR_pause, ## __VA_ARGS__)
#define r_pciconfig_iobase(...) native_syscall(__NR_pciconfig_iobase, ## __VA_ARGS__)
#define r_pciconfig_read(...) native_syscall(__NR_pciconfig_read, ## __VA_ARGS__)
#define r_pciconfig_write(...) native_syscall(__NR_pciconfig_write, ## __VA_ARGS__)
#define r_perf_event_open(...) native_syscall(__NR_perf_event_open, ## __VA_ARGS__)
#define r_perfmonctl(...) native_syscall(__NR_perfmonctl, ## __VA_ARGS__)
#define r_personality(...) native_syscall(__NR_personality, ## __VA_ARGS__)
#define r_phys(...) native_syscall(__NR_phys, ## __VA_ARGS__)
#define r_pipe(...) native_syscall(__NR_pipe, ## __VA_ARGS__)
#define r_pipe2(...) native_syscall(__NR_pipe2, ## __VA_ARGS__)
#define r_pivot_root(...) native_syscall(__NR_pivot_root, ## __VA_ARGS__)
#define r_pkey_alloc(...) native_syscall(__NR_pkey_alloc, ## __VA_ARGS__)
#define r_pkey_free(...) native_syscall(__NR_pkey_free, ## __VA_ARGS__)
#define r_pkey_mprotect(...) native_syscall(__NR_pkey_mprotect, ## __VA_ARGS__)
#define r_poll(...) native_syscall(__NR_poll, ## __VA_ARGS__)
#define r_posix_fadvise(...) native_syscall(__NR_posix_fadvise, ## __VA_ARGS__)
#define r_ppoll(...) native_syscall(__NR_ppoll, ## __VA_ARGS__)
#define r_prctl(...) native_syscall(__NR_prctl, ## __VA_ARGS__)
#define r_pread(...) native_syscall(__NR_pread, ## __VA_ARGS__)
#define r_pread64(...) native_syscall(__NR_pread64, ## __VA_ARGS__)
#define r_preadv(...) native_syscall(__NR_preadv, ## __VA_ARGS__)
#define r_preadv2(...) native_syscall(__NR_preadv2, ## __VA_ARGS__)
#define r_prlimit(...) native_syscall(__NR_prlimit, ## __VA_ARGS__)
#define r_prlimit64(...) native_syscall(__NR_prlimit64, ## __VA_ARGS__)
#define r_process_vm_readv(...) native_syscall(__NR_process_vm_readv, ## __VA_ARGS__)
#define r_process_vm_writev(...) native_syscall(__NR_process_vm_writev, ## __VA_ARGS__)
#define r_prof(...) native_syscall(__NR_prof, ## __VA_ARGS__)
#define r_pselect(...) native_syscall(__NR_pselect, ## __VA_ARGS__)
#define r_pselect6(...) native_syscall(__NR_pselect6, ## __VA_ARGS__)
#define r_ptrace(...) native_syscall(__NR_ptrace, ## __VA_ARGS__)
#define r_putmsg(...) native_syscall(__NR_putmsg, ## __VA_ARGS__)
#define r_putpmsg(...) native_syscall(__NR_putpmsg, ## __VA_ARGS__)
#define r_pwrite(...) native_syscall(__NR_pwrite, ## __VA_ARGS__)
#define r_pwrite64(...) native_syscall(__NR_pwrite64, ## __VA_ARGS__)
#define r_pwritev(...) native_syscall(__NR_pwritev, ## __VA_ARGS__)
#define r_pwritev2(...) native_syscall(__NR_pwritev2, ## __VA_ARGS__)
#define r_query_module(...) native_syscall(__NR_query_module, ## __VA_ARGS__)
#define r_quotactl(...) native_syscall(__NR_quotactl, ## __VA_ARGS__)
#define r_read(...) native_syscall(__NR_read, ## __VA_ARGS__)
#define r_readahead(...) native_syscall(__NR_readahead, ## __VA_ARGS__)
#define r_readdir(...) native_syscall(__NR_readdir, ## __VA_ARGS__)
#define r_readlink(...) native_syscall(__NR_readlink, ## __VA_ARGS__)
#define r_readlinkat(...) native_syscall(__NR_readlinkat, ## __VA_ARGS__)
#define r_readv(...) native_syscall(__NR_readv, ## __VA_ARGS__)
#define r_reboot(...) native_syscall(__NR_reboot, ## __VA_ARGS__)
#define r_recv(...) native_syscall(__NR_recv, ## __VA_ARGS__)
#define r_recvfrom(...) native_syscall(__NR_recvfrom, ## __VA_ARGS__)
#define r_recvmmsg(...) native_syscall(__NR_recvmmsg, ## __VA_ARGS__)
#define r_recvmsg(...) native_syscall(__NR_recvmsg, ## __VA_ARGS__)
#define r_remap_file_pages(...) native_syscall(__NR_remap_file_pages, ## __VA_ARGS__)
#define r_removexattr(...) native_syscall(__NR_removexattr, ## __VA_ARGS__)
#define r_rename(...) native_syscall(__NR_rename, ## __VA_ARGS__)
#define r_renameat(...) native_syscall(__NR_renameat, ## __VA_ARGS__)
#define r_renameat2(...) native_syscall(__NR_renameat2, ## __VA_ARGS__)
#define r_request_key(...) native_syscall(__NR_request_key, ## __VA_ARGS__)
#define r_restart_syscall(...) native_syscall(__NR_restart_syscall, ## __VA_ARGS__)
#define r_rmdir(...) native_syscall(__NR_rmdir, ## __VA_ARGS__)
#define r_rt_sigaction(...) native_syscall(__NR_rt_sigaction, ## __VA_ARGS__)
#define r_rt_sigpending(...) native_syscall(__NR_rt_sigpending, ## __VA_ARGS__)
#define r_rt_sigprocmask(...) native_syscall(__NR_rt_sigprocmask, ## __VA_ARGS__)
#define r_rt_sigqueueinfo(...) native_syscall(__NR_rt_sigqueueinfo, ## __VA_ARGS__)
#define r_rt_sigreturn(...) native_syscall(__NR_rt_sigreturn, ## __VA_ARGS__)
#define r_rt_sigsuspend(...) native_syscall(__NR_rt_sigsuspend, ## __VA_ARGS__)
#define r_rt_sigtimedwait(...) native_syscall(__NR_rt_sigtimedwait, ## __VA_ARGS__)
#define r_rt_tgsigqueueinfo(...) native_syscall(__NR_rt_tgsigqueueinfo, ## __VA_ARGS__)
#define r_s390_pci_mmio_read(...) native_syscall(__NR_s390_pci_mmio_read, ## __VA_ARGS__)
#define r_s390_pci_mmio_write(...) native_syscall(__NR_s390_pci_mmio_write, ## __VA_ARGS__)
#define r_s390_runtime_instr(...) native_syscall(__NR_s390_runtime_instr, ## __VA_ARGS__)
#define r_sbrk(...) native_syscall(__NR_sbrk, ## __VA_ARGS__)
#define r_sched_get_priority_max(...) native_syscall(__NR_sched_get_priority_max, ## __VA_ARGS__)
#define r_sched_get_priority_min(...) native_syscall(__NR_sched_get_priority_min, ## __VA_ARGS__)
#define r_sched_getaffinity(...) native_syscall(__NR_sched_getaffinity, ## __VA_ARGS__)
#define r_sched_getattr(...) native_syscall(__NR_sched_getattr, ## __VA_ARGS__)
#define r_sched_getparam(...) native_syscall(__NR_sched_getparam, ## __VA_ARGS__)
#define r_sched_getscheduler(...) native_syscall(__NR_sched_getscheduler, ## __VA_ARGS__)
#define r_sched_rr_get_interval(...) native_syscall(__NR_sched_rr_get_interval, ## __VA_ARGS__)
#define r_sched_setaffinity(...) native_syscall(__NR_sched_setaffinity, ## __VA_ARGS__)
#define r_sched_setattr(...) native_syscall(__NR_sched_setattr, ## __VA_ARGS__)
#define r_sched_setparam(...) native_syscall(__NR_sched_setparam, ## __VA_ARGS__)
#define r_sched_setscheduler(...) native_syscall(__NR_sched_setscheduler, ## __VA_ARGS__)
#define r_sched_yield(...) native_syscall(__NR_sched_yield, ## __VA_ARGS__)
#define r_seccomp(...) native_syscall(__NR_seccomp, ## __VA_ARGS__)
#define r_security(...) native_syscall(__NR_security, ## __VA_ARGS__)
#define r_select(...) native_syscall(__NR_select, ## __VA_ARGS__)
#define r_select_tut(...) native_syscall(__NR_select_tut, ## __VA_ARGS__)
#define r_semctl(...) native_syscall(__NR_semctl, ## __VA_ARGS__)
#define r_semget(...) native_syscall(__NR_semget, ## __VA_ARGS__)
#define r_semop(...) native_syscall(__NR_semop, ## __VA_ARGS__)
#define r_semtimedop(...) native_syscall(__NR_semtimedop, ## __VA_ARGS__)
#define r_send(...) native_syscall(__NR_send, ## __VA_ARGS__)
#define r_sendfile(...) native_syscall(__NR_sendfile, ## __VA_ARGS__)
#define r_sendfile64(...) native_syscall(__NR_sendfile64, ## __VA_ARGS__)
#define r_sendmmsg(...) native_syscall(__NR_sendmmsg, ## __VA_ARGS__)
#define r_sendmsg(...) native_syscall(__NR_sendmsg, ## __VA_ARGS__)
#define r_sendto(...) native_syscall(__NR_sendto, ## __VA_ARGS__)
#define r_set_mempolicy(...) native_syscall(__NR_set_mempolicy, ## __VA_ARGS__)
#define r_set_robust_list(...) native_syscall(__NR_set_robust_list, ## __VA_ARGS__)
#define r_set_thread_area(...) native_syscall(__NR_set_thread_area, ## __VA_ARGS__)
#define r_set_tid_address(...) native_syscall(__NR_set_tid_address, ## __VA_ARGS__)
#define r_setcontext(...) native_syscall(__NR_setcontext, ## __VA_ARGS__)
#define r_setdomainname(...) native_syscall(__NR_setdomainname, ## __VA_ARGS__)
#define r_setegid(...) native_syscall(__NR_setegid, ## __VA_ARGS__)
#define r_seteuid(...) native_syscall(__NR_seteuid, ## __VA_ARGS__)
#define r_setfsgid(...) native_syscall(__NR_setfsgid, ## __VA_ARGS__)
#define r_setfsgid32(...) native_syscall(__NR_setfsgid32, ## __VA_ARGS__)
#define r_setfsuid(...) native_syscall(__NR_setfsuid, ## __VA_ARGS__)
#define r_setfsuid32(...) native_syscall(__NR_setfsuid32, ## __VA_ARGS__)
#define r_setgid(...) native_syscall(__NR_setgid, ## __VA_ARGS__)
#define r_setgid32(...) native_syscall(__NR_setgid32, ## __VA_ARGS__)
#define r_setgroups(...) native_syscall(__NR_setgroups, ## __VA_ARGS__)
#define r_setgroups32(...) native_syscall(__NR_setgroups32, ## __VA_ARGS__)
#define r_sethostid(...) native_syscall(__NR_sethostid, ## __VA_ARGS__)
#define r_sethostname(...) native_syscall(__NR_sethostname, ## __VA_ARGS__)
#define r_setitimer(...) native_syscall(__NR_setitimer, ## __VA_ARGS__)
#define r_setns(...) native_syscall(__NR_setns, ## __VA_ARGS__)
#define r_setpgid(...) native_syscall(__NR_setpgid, ## __VA_ARGS__)
#define r_setpgrp(...) native_syscall(__NR_setpgrp, ## __VA_ARGS__)
#define r_setpriority(...) native_syscall(__NR_setpriority, ## __VA_ARGS__)
#define r_setregid(...) native_syscall(__NR_setregid, ## __VA_ARGS__)
#define r_setregid32(...) native_syscall(__NR_setregid32, ## __VA_ARGS__)
#define r_setresgid(...) native_syscall(__NR_setresgid, ## __VA_ARGS__)
#define r_setresgid32(...) native_syscall(__NR_setresgid32, ## __VA_ARGS__)
#define r_setresuid(...) native_syscall(__NR_setresuid, ## __VA_ARGS__)
#define r_setresuid32(...) native_syscall(__NR_setresuid32, ## __VA_ARGS__)
#define r_setreuid(...) native_syscall(__NR_setreuid, ## __VA_ARGS__)
#define r_setreuid32(...) native_syscall(__NR_setreuid32, ## __VA_ARGS__)
#define r_setrlimit(...) native_syscall(__NR_setrlimit, ## __VA_ARGS__)
#define r_setsid(...) native_syscall(__NR_setsid, ## __VA_ARGS__)
#define r_setsockopt(...) native_syscall(__NR_setsockopt, ## __VA_ARGS__)
#define r_settimeofday(...) native_syscall(__NR_settimeofday, ## __VA_ARGS__)
#define r_setuid(...) native_syscall(__NR_setuid, ## __VA_ARGS__)
#define r_setuid32(...) native_syscall(__NR_setuid32, ## __VA_ARGS__)
#define r_setup(...) native_syscall(__NR_setup, ## __VA_ARGS__)
#define r_setxattr(...) native_syscall(__NR_setxattr, ## __VA_ARGS__)
#define r_sgetmask(...) native_syscall(__NR_sgetmask, ## __VA_ARGS__)
#define r_shmat(...) native_syscall(__NR_shmat, ## __VA_ARGS__)
#define r_shmctl(...) native_syscall(__NR_shmctl, ## __VA_ARGS__)
#define r_shmdt(...) native_syscall(__NR_shmdt, ## __VA_ARGS__)
#define r_shmget(...) native_syscall(__NR_shmget, ## __VA_ARGS__)
#define r_shmop(...) native_syscall(__NR_shmop, ## __VA_ARGS__)
#define r_shutdown(...) native_syscall(__NR_shutdown, ## __VA_ARGS__)
#define r_sigaction(...) native_syscall(__NR_sigaction, ## __VA_ARGS__)
#define r_sigaltstack(...) native_syscall(__NR_sigaltstack, ## __VA_ARGS__)
#define r_signal(...) native_syscall(__NR_signal, ## __VA_ARGS__)
#define r_signalfd(...) native_syscall(__NR_signalfd, ## __VA_ARGS__)
#define r_signalfd4(...) native_syscall(__NR_signalfd4, ## __VA_ARGS__)
#define r_sigpending(...) native_syscall(__NR_sigpending, ## __VA_ARGS__)
#define r_sigprocmask(...) native_syscall(__NR_sigprocmask, ## __VA_ARGS__)
#define r_sigqueue(...) native_syscall(__NR_sigqueue, ## __VA_ARGS__)
#define r_sigreturn(...) native_syscall(__NR_sigreturn, ## __VA_ARGS__)
#define r_sigsuspend(...) native_syscall(__NR_sigsuspend, ## __VA_ARGS__)
#define r_sigtimedwait(...) native_syscall(__NR_sigtimedwait, ## __VA_ARGS__)
#define r_sigwaitinfo(...) native_syscall(__NR_sigwaitinfo, ## __VA_ARGS__)
#define r_socket(...) native_syscall(__NR_socket, ## __VA_ARGS__)
#define r_socketcall(...) native_syscall(__NR_socketcall, ## __VA_ARGS__)
#define r_socketpair(...) native_syscall(__NR_socketpair, ## __VA_ARGS__)
#define r_splice(...) native_syscall(__NR_splice, ## __VA_ARGS__)
#define r_spu_create(...) native_syscall(__NR_spu_create, ## __VA_ARGS__)
#define r_spu_run(...) native_syscall(__NR_spu_run, ## __VA_ARGS__)
#define r_ssetmask(...) native_syscall(__NR_ssetmask, ## __VA_ARGS__)
#define r_stat(...) native_syscall(__NR_stat, ## __VA_ARGS__)
#define r_stat64(...) native_syscall(__NR_stat64, ## __VA_ARGS__)
#define r_statfs(...) native_syscall(__NR_statfs, ## __VA_ARGS__)
#define r_statfs64(...) native_syscall(__NR_statfs64, ## __VA_ARGS__)
#define r_statvfs(...) native_syscall(__NR_statvfs, ## __VA_ARGS__)
#define r_statx(...) native_syscall(__NR_statx, ## __VA_ARGS__)
#define r_stime(...) native_syscall(__NR_stime, ## __VA_ARGS__)
#define r_stty(...) native_syscall(__NR_stty, ## __VA_ARGS__)
#define r_subpage_prot(...) native_syscall(__NR_subpage_prot, ## __VA_ARGS__)
#define r_swapoff(...) native_syscall(__NR_swapoff, ## __VA_ARGS__)
#define r_swapon(...) native_syscall(__NR_swapon, ## __VA_ARGS__)
#define r_symlink(...) native_syscall(__NR_symlink, ## __VA_ARGS__)
#define r_symlinkat(...) native_syscall(__NR_symlinkat, ## __VA_ARGS__)
#define r_sync(...) native_syscall(__NR_sync, ## __VA_ARGS__)
#define r_sync_file_range(...) native_syscall(__NR_sync_file_range, ## __VA_ARGS__)
#define r_sync_file_range2(...) native_syscall(__NR_sync_file_range2, ## __VA_ARGS__)
#define r_syncfs(...) native_syscall(__NR_syncfs, ## __VA_ARGS__)
#define r_syscall(...) native_syscall(__NR_syscall, ## __VA_ARGS__)
#define r_syscalls(...) native_syscall(__NR_syscalls, ## __VA_ARGS__)
#define r_sysctl(...) native_syscall(__NR_sysctl, ## __VA_ARGS__)
#define r_sysfs(...) native_syscall(__NR_sysfs, ## __VA_ARGS__)
#define r_sysinfo(...) native_syscall(__NR_sysinfo, ## __VA_ARGS__)
#define r_syslog(...) native_syscall(__NR_syslog, ## __VA_ARGS__)
#define r_tee(...) native_syscall(__NR_tee, ## __VA_ARGS__)
#define r_tgkill(...) native_syscall(__NR_tgkill, ## __VA_ARGS__)
#define r_time(...) native_syscall(__NR_time, ## __VA_ARGS__)
#define r_timer_create(...) native_syscall(__NR_timer_create, ## __VA_ARGS__)
#define r_timer_delete(...) native_syscall(__NR_timer_delete, ## __VA_ARGS__)
#define r_timer_getoverrun(...) native_syscall(__NR_timer_getoverrun, ## __VA_ARGS__)
#define r_timer_gettime(...) native_syscall(__NR_timer_gettime, ## __VA_ARGS__)
#define r_timer_settime(...) native_syscall(__NR_timer_settime, ## __VA_ARGS__)
#define r_timerfd_create(...) native_syscall(__NR_timerfd_create, ## __VA_ARGS__)
#define r_timerfd_gettime(...) native_syscall(__NR_timerfd_gettime, ## __VA_ARGS__)
#define r_timerfd_settime(...) native_syscall(__NR_timerfd_settime, ## __VA_ARGS__)
#define r_times(...) native_syscall(__NR_times, ## __VA_ARGS__)
#define r_tkill(...) native_syscall(__NR_tkill, ## __VA_ARGS__)
#define r_truncate(...) native_syscall(__NR_truncate, ## __VA_ARGS__)
#define r_truncate64(...) native_syscall(__NR_truncate64, ## __VA_ARGS__)
#define r_tuxcall(...) native_syscall(__NR_tuxcall, ## __VA_ARGS__)
#define r_ugetrlimit(...) native_syscall(__NR_ugetrlimit, ## __VA_ARGS__)
#define r_umask(...) native_syscall(__NR_umask, ## __VA_ARGS__)
#define r_umount(...) native_syscall(__NR_umount, ## __VA_ARGS__)
#define r_umount2(...) native_syscall(__NR_umount2, ## __VA_ARGS__)
#define r_uname(...) native_syscall(__NR_uname, ## __VA_ARGS__)
#define r_unimplemented(...) native_syscall(__NR_unimplemented, ## __VA_ARGS__)
#define r_unlink(...) native_syscall(__NR_unlink, ## __VA_ARGS__)
#define r_unlinkat(...) native_syscall(__NR_unlinkat, ## __VA_ARGS__)
#define r_unshare(...) native_syscall(__NR_unshare, ## __VA_ARGS__)
#define r_uselib(...) native_syscall(__NR_uselib, ## __VA_ARGS__)
#define r_userfaultfd(...) native_syscall(__NR_userfaultfd, ## __VA_ARGS__)
#define r_ustat(...) native_syscall(__NR_ustat, ## __VA_ARGS__)
#define r_utime(...) native_syscall(__NR_utime, ## __VA_ARGS__)
#define r_utimensat(...) native_syscall(__NR_utimensat, ## __VA_ARGS__)
#define r_utimes(...) native_syscall(__NR_utimes, ## __VA_ARGS__)
#define r_vfork(...) native_syscall(__NR_vfork, ## __VA_ARGS__)
#define r_vhangup(...) native_syscall(__NR_vhangup, ## __VA_ARGS__)
#define r_vm86(...) native_syscall(__NR_vm86, ## __VA_ARGS__)
#define r_vm86old(...) native_syscall(__NR_vm86old, ## __VA_ARGS__)
#define r_vmsplice(...) native_syscall(__NR_vmsplice, ## __VA_ARGS__)
#define r_vserver(...) native_syscall(__NR_vserver, ## __VA_ARGS__)
#define r_wait(...) native_syscall(__NR_wait, ## __VA_ARGS__)
#define r_wait3(...) native_syscall(__NR_wait3, ## __VA_ARGS__)
#define r_wait4(...) native_syscall(__NR_wait4, ## __VA_ARGS__)
#define r_waitid(...) native_syscall(__NR_waitid, ## __VA_ARGS__)
#define r_waitpid(...) native_syscall(__NR_waitpid, ## __VA_ARGS__)
#define r_write(...) native_syscall(__NR_write, ## __VA_ARGS__)
#define r_writev(...) native_syscall(__NR_writev, ## __VA_ARGS__)
#endif
