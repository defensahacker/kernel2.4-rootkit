# Hijacking system calls on 2.4 linux kernels

## Intro

On linux kernels 2.4.x when we load a module (insmod xxx) into the kernel, remember that kernel is just a C program, we can access to any global variable: the list of loaded modules, the uptime of the system, etc,.., and to the system call table:

```
extern void *sys_call_table[];
```

Note: On 2.6.x kernel, we CAN'T export the system call table, this means, that we can't use this method to hijack system calls.
System call table
The system call table its an array of 238 elements (kernel 2.4.18), where each element its an address to a system call,
i.e: sys_call_table[1] is the address for exit() system call.
To look how system call table is created, take a look to this file: /usr/src/linux/arch/i386/kernel/entry.S:

```
...

* entry.S contains the system-call and fault low-level handling routines.
* This also contains the timer-interrupt handler, as well as all interrupts
* and faults that can result in a task-switch.

...

ENTRY(system_call)
	pushl %eax                      # save orig_eax
	SAVE_ALL
	GET_CURRENT(%ebx)
	testb $0x02,tsk_ptrace(%ebx)    # PT_TRACESYS
	jne tracesys
	cmpl $(NR_syscalls),%eax
	jae badsys
	call *SYMBOL_NAME(sys_call_table)(,%eax,4)
	movl %eax,EAX(%esp)             # save the return value
ENTRY(ret_from_sys_call)
	cli                             # need_resched and signals atomic test
	cmpl $0,need_resched(%ebx)
	jne reschedule
	cmpl $0,sigpending(%ebx)
	jne signal_return
restore_all:
	RESTORE_ALL

	ALIGN
signal_return:
	sti

...

ENTRY(ret_from_intr)
	GET_CURRENT(%ebx)
ret_from_exception:
	movl EFLAGS(%esp),%eax          # mix EFLAGS and CS

...

ENTRY(divide_error)

...

ENTRY(coprocessor_error)

...

ENTRY(page_fault)

...

.data
ENTRY(sys_call_table)
	.long SYMBOL_NAME(sys_ni_syscall)       /* 0  -  old "setup()" system call*/
	.long SYMBOL_NAME(sys_exit)
	.long SYMBOL_NAME(sys_fork)
	.long SYMBOL_NAME(sys_read)
	.long SYMBOL_NAME(sys_write)
	.long SYMBOL_NAME(sys_open)             /* 5 */
	.long SYMBOL_NAME(sys_close)
	.long SYMBOL_NAME(sys_waitpid)
        .long SYMBOL_NAME(sys_creat)
	.long SYMBOL_NAME(sys_link)
	.long SYMBOL_NAME(sys_unlink)           /* 10 */
	.long SYMBOL_NAME(sys_execve)
...
	.long SYMBOL_NAME(sys_getdents64)       /* 220 */
...
	.long SYMBOL_NAME(sys_readahead)        /* 225 */
...
	.long SYMBOL_NAME(sys_ni_syscall)       /* reserved for fremovexattr */ /* 237 */
```

## Dumping the system call table

To look and check the sys_call_table, you can use a module called syscalltable-checker.
usage & example:

```
# make
# insmod syscalltable-checker
# tail -240 /var/log/messages (or dmesg)
----   sys call table checker loaded!   ----
----          by jack                   ----
----  sys_call_table is at: 0xc02984d8  ----
----  Starting to dump sys call table   ----
syscall #1 [__NR_exit] at -> 0xc0114558
syscall #2 [__NR_fork] at -> 0xc0105824
syscall #3 [__NR_read] at -> 0xc012c300
syscall #4 [__NR_write] at -> 0xc012c3e0
syscall #5 [__NR_open] at -> 0xc012be74
syscall #6 [__NR_close] at -> 0xc012bf84
syscall #7 [__NR_waitpid] at -> 0xc0114910
syscall #8 [__NR_creat] at -> 0xc012bf08
syscall #9 [__NR_link] at -> 0xc01366a0
syscall #10 [__NR_unlink] at -> 0xc013633c
syscall #11 [__NR_execve] at -> 0xc0105888
syscall #12 [__NR_chdir] at -> 0xc012b5bc
syscall #13 [__NR_time] at -> 0xc0114e10
syscall #14 [__NR_mknod] at -> 0xc0135c0c
syscall #15 [__NR_chmod] at -> 0xc012b8d8
syscall #16 [__NR_lchown] at -> 0xc011c72c
syscall #17 [__NR_break] at -> 0xc011a440
syscall #18 [__NR_oldstat] at -> 0xc013229c
syscall #19 [__NR_lseek] at -> 0xc012c190
syscall #20 [__NR_getpid] at -> 0xc01188e8
syscall #21 [__NR_mount] at -> 0xc01403c8
syscall #22 [__NR_umount] at -> 0xc013fb54
syscall #23 [__NR_setuid] at -> 0xc011c828
syscall #24 [__NR_getuid] at -> 0xc011cbd4
syscall #25 [__NR_stime] at -> 0xc0114e64
syscall #26 [__NR_ptrace] at -> 0xc010972c
syscall #27 [__NR_alarm] at -> 0xc011889c
syscall #28 [__NR_oldfstat] at -> 0xc0132460
syscall #29 [__NR_pause] at -> 0xc010b3e0
syscall #30 [__NR_utime] at -> 0xc012b2dc
syscall #31 [__NR_stty] at -> 0xc011a440
syscall #32 [__NR_gtty] at -> 0xc011a440
syscall #33 [__NR_access] at -> 0xc012b498
syscall #34 [__NR_nice] at -> 0xc010f940
syscall #35 [__NR_ftime] at -> 0xc011a440
syscall #36 [__NR_sync] at -> 0xc012d448
syscall #37 [__NR_kill] at -> 0xc0119c90
syscall #38 [__NR_rename] at -> 0xc0136fc0
syscall #39 [__NR_mkdir] at -> 0xc0135e4c
syscall #40 [__NR_rmdir] at -> 0xc0136114
syscall #41 [__NR_dup] at -> 0xc01379f8
syscall #42 [__NR_pipe] at -> 0xc010ada0
syscall #43 [__NR_times] at -> 0xc011b0f0
syscall #44 [__NR_prof] at -> 0xc011a440
syscall #45 [__NR_brk] at -> 0xc011e4d0
syscall #46 [__NR_setgid] at -> 0xc011c7e0
syscall #47 [__NR_getgid] at -> 0xc011cc1c
syscall #48 [__NR_signal] at -> 0xc011a2d4
syscall #49 [__NR_geteuid] at -> 0xc011cbf8
syscall #50 [__NR_getegid] at -> 0xc011cc40
syscall #51 [__NR_acct] at -> 0xc0117470
syscall #52 [__NR_umount2] at -> 0xc013fa9c
syscall #53 [__NR_lock] at -> 0xc011a440
syscall #54 [__NR_ioctl] at -> 0xc01381bc
syscall #55 [__NR_fcntl] at -> 0xc0137cd0
syscall #56 [__NR_mpx] at -> 0xc011a440
syscall #57 [__NR_setpgid] at -> 0xc011b14c
syscall #58 [__NR_ulimit] at -> 0xc011a440
syscall #59 [__NR_oldolduname] at -> 0xc010b2ec
syscall #60 [__NR_umask] at -> 0xc011baf8
syscall #61 [__NR_chroot] at -> 0xc012b75c
syscall #62 [__NR_ustat] at -> 0xc01307b8
syscall #63 [__NR_dup2] at -> 0xc0137948
syscall #64 [__NR_getppid] at -> 0xc01188f8
syscall #65 [__NR_getpgrp] at -> 0xc011b288
syscall #66 [__NR_setsid] at -> 0xc011b2e8
syscall #67 [__NR_sigaction] at -> 0xc0105da4
syscall #68 [__NR_sgetmask] at -> 0xc011a27c
syscall #69 [__NR_ssetmask] at -> 0xc011a28c
syscall #70 [__NR_setreuid] at -> 0xc011c7f0
syscall #71 [__NR_setregid] at -> 0xc011c7a8
syscall #72 [__NR_sigsuspend] at -> 0xc0105bf8
syscall #73 [__NR_sigpending] at -> 0xc011a008
syscall #74 [__NR_sethostname] at -> 0xc011b504
syscall #75 [__NR_setrlimit] at -> 0xc011b778
syscall #76 [__NR_getrlimit] at -> 0xc011b6e8
syscall #77 [__NR_getrusage] at -> 0xc011bacc
syscall #78 [__NR_gettimeofday] at -> 0xc0114ed8
syscall #79 [__NR_settimeofday] at -> 0xc0114ffc
syscall #80 [__NR_getgroups] at -> 0xc011cad8
syscall #81 [__NR_setgroups] at -> 0xc011cb4c
syscall #82 [__NR_select] at -> 0xc010afc4
syscall #83 [__NR_symlink] at -> 0xc01364f4
syscall #84 [__NR_oldlstat] at -> 0xc0132380
syscall #85 [__NR_readlink] at -> 0xc0132520
syscall #86 [__NR_uselib] at -> 0xc0132900
syscall #87 [__NR_swapon] at -> 0xc0128384
syscall #88 [__NR_reboot] at -> 0xc011a618
syscall #89 [__NR_readdir] at -> 0xc013859c
syscall #90 [__NR_mmap] at -> 0xc010aea0
syscall #91 [__NR_munmap] at -> 0xc011f320
syscall #92 [__NR_truncate] at -> 0xc012acd8
syscall #93 [__NR_ftruncate] at -> 0xc012aeb8
syscall #94 [__NR_fchmod] at -> 0xc012b850
syscall #95 [__NR_fchown] at -> 0xc011c768
syscall #96 [__NR_getpriority] at -> 0xc011a5bc
syscall #97 [__NR_setpriority] at -> 0xc011a4e8
syscall #98 [__NR_profil] at -> 0xc011a440
syscall #99 [__NR_statfs] at -> 0xc012ab48
syscall #100 [__NR_fstatfs] at -> 0xc012abe8
syscall #101 [__NR_ioperm] at -> 0xc010a0a8
syscall #102 [__NR_socketcall] at -> 0xc02069e8
syscall #103 [__NR_syslog] at -> 0xc0111a14
syscall #104 [__NR_setitimer] at -> 0xc0114bf0
syscall #105 [__NR_getitimer] at -> 0xc0114a3c
syscall #106 [__NR_stat] at -> 0xc0132310
syscall #107 [__NR_lstat] at -> 0xc01323f0
syscall #108 [__NR_fstat] at -> 0xc01324c0
syscall #109 [__NR_olduname] at -> 0xc010b264
syscall #110 [__NR_iopl] at -> 0xc010a188
syscall #111 [__NR_vhangup] at -> 0xc012bfd8
syscall #112 [__NR_idle] at -> 0xc011a440
syscall #113 [__NR_vm86old] at -> 0xc01086ac
syscall #114 [__NR_wait4] at -> 0xc0114568
syscall #115 [__NR_swapoff] at -> 0xc0127f14
syscall #116 [__NR_sysinfo] at -> 0xc0114ce0
syscall #117 [__NR_ipc] at -> 0xc010b03c
syscall #118 [__NR_fsync] at -> 0xc012d4b4
syscall #119 [__NR_sigreturn] at -> 0xc0105ff4
syscall #120 [__NR_clone] at -> 0xc0105840
syscall #121 [__NR_setdomainname] at -> 0xc011b608
syscall #122 [__NR_uname] at -> 0xc011b48c
syscall #123 [__NR_modify_ldt] at -> 0xc010a4d8
syscall #124 [__NR_adjtimex] at -> 0xc0115498
syscall #125 [__NR_mprotect] at -> 0xc012336c
syscall #126 [__NR_sigprocmask] at -> 0xc011a018
syscall #127 [__NR_create_module] at -> 0xc0112318
syscall #128 [__NR_init_module] at -> 0xc0112458
syscall #129 [__NR_delete_module] at -> 0xc0112ac4
syscall #130 [__NR_get_kernel_syms] at -> 0xc01134e8
syscall #131 [__NR_quotactl] at -> 0xc0141130
syscall #132 [__NR_getpgid] at -> 0xc011b238
syscall #133 [__NR_fchdir] at -> 0xc012b69c
syscall #134 [__NR_bdflush] at -> 0xc012fdb4
syscall #135 [__NR_sysfs] at -> 0xc0130274
syscall #136 [__NR_personality] at -> 0xc0111594
syscall #137 [__NR_afs_syscall] at -> 0xc011a440
syscall #138 [__NR_setfsuid] at -> 0xc011cab8
syscall #139 [__NR_setfsgid] at -> 0xc011cac8
syscall #140 [__NR__llseek] at -> 0xc012c228
syscall #141 [__NR_getdents] at -> 0xc01386ec
syscall #142 [__NR__newselect] at -> 0xc0138d7c
syscall #143 [__NR_flock] at -> 0xc013b240
syscall #144 [__NR_msync] at -> 0xc012199c
syscall #145 [__NR_readv] at -> 0xc012c72c
syscall #146 [__NR_writev] at -> 0xc012c780
syscall #147 [__NR_getsid] at -> 0xc011b298
syscall #148 [__NR_fdatasync] at -> 0xc012d55c
syscall #149 [__NR__sysctl] at -> 0xc0115ed0
syscall #150 [__NR_mlock] at -> 0xc012398c
syscall #151 [__NR_munlock] at -> 0xc0123a44
syscall #152 [__NR_mlockall] at -> 0xc0123b54
syscall #153 [__NR_munlockall] at -> 0xc0123be4
syscall #154 [__NR_sched_setparam] at -> 0xc010fb5c
syscall #155 [__NR_sched_getparam] at -> 0xc010fbd8
syscall #156 [__NR_sched_setscheduler] at -> 0xc010fb44
syscall #157 [__NR_sched_getscheduler] at -> 0xc010fb74
syscall #158 [__NR_sched_yield] at -> 0xc010fc7c
syscall #159 [__NR_sched_get_priority_max] at -> 0xc010fcdc
syscall #160 [__NR_sched_get_priority_min] at -> 0xc010fd08
syscall #161 [__NR_sched_rr_get_interval] at -> 0xc010fd30
syscall #162 [__NR_nanosleep] at -> 0xc0118958
syscall #163 [__NR_mremap] at -> 0xc01243ac
syscall #164 [__NR_setresuid] at -> 0xc011c838
syscall #165 [__NR_getresuid] at -> 0xc011c884
syscall #166 [__NR_vm86] at -> 0xc01087a0
syscall #167 [__NR_query_module] at -> 0xc0113390
syscall #168 [__NR_poll] at -> 0xc01394c0
syscall #169 [__NR_nfsservctl] at -> 0xc016ef4c
syscall #170 [__NR_setresgid] at -> 0xc011c978
syscall #171 [__NR_getresgid] at -> 0xc011c9c4
syscall #172 [__NR_prctl] at -> 0xc011bb14
syscall #173 [__NR_rt_sigreturn] at -> 0xc01060c8
syscall #174 [__NR_rt_sigaction] at -> 0xc011a188
syscall #175 [__NR_rt_sigprocmask] at -> 0xc0119740
syscall #176 [__NR_rt_sigpending] at -> 0xc011998c
syscall #177 [__NR_rt_sigtimedwait] at -> 0xc01199a0
syscall #178 [__NR_rt_sigqueueinfo] at -> 0xc0119ce8
syscall #179 [__NR_rt_sigsuspend] at -> 0xc0105c84
syscall #180 [__NR_pread] at -> 0xc012c7d4
syscall #181 [__NR_pwrite] at -> 0xc012c8c0
syscall #182 [__NR_chown] at -> 0xc011c6f0
syscall #183 [__NR_getcwd] at -> 0xc013cd4c
syscall #184 [__NR_capget] at -> 0xc0117480
syscall #185 [__NR_capset] at -> 0xc0117688
syscall #186 [__NR_sigaltstack] at -> 0xc0105ea8
syscall #187 [__NR_sendfile] at -> 0xc0121024
syscall #188 [__NR_getpmsg] at -> 0xc011a440
syscall #189 [__NR_putpmsg] at -> 0xc011a440
syscall #190 [__NR_vfork] at -> 0xc0105868
syscall #191 [__NR_ugetrlimit] at -> 0xc011b68c
syscall #192 [__NR_mmap2] at -> 0xc010adfc
syscall #193 [__NR_truncate64] at -> 0xc012b00c
syscall #194 [__NR_ftruncate64] at -> 0xc012b190
syscall #195 [__NR_stat64] at -> 0xc013273c
syscall #196 [__NR_lstat64] at -> 0xc01327b0
syscall #197 [__NR_fstat64] at -> 0xc0132820
syscall #198 [__NR_lchown32] at -> 0xc012baa4
syscall #199 [__NR_getuid32] at -> 0xc011890c
syscall #200 [__NR_getgid32] at -> 0xc011892c
syscall #201 [__NR_geteuid32] at -> 0xc011891c
syscall #202 [__NR_getegid32] at -> 0xc011893c
syscall #203 [__NR_setreuid32] at -> 0xc011a9b4
syscall #204 [__NR_setregid32] at -> 0xc011a814
syscall #205 [__NR_getgroups32] at -> 0xc011b34c
syscall #206 [__NR_setgroups32] at -> 0xc011b39c
syscall #207 [__NR_fchown32] at -> 0xc012baec
syscall #208 [__NR_setresuid32] at -> 0xc011ac70
syscall #209 [__NR_getresuid32] at -> 0xc011ae14
syscall #210 [__NR_setresgid32] at -> 0xc011aeb4
syscall #211 [__NR_getresgid32] at -> 0xc011af7c
syscall #212 [__NR_chown32] at -> 0xc012ba5c
syscall #213 [__NR_setuid32] at -> 0xc011ab30
syscall #214 [__NR_setgid32] at -> 0xc011a8d8
syscall #215 [__NR_setfsuid32] at -> 0xc011b014
syscall #216 [__NR_setfsgid32] at -> 0xc011b0a0
syscall #217 [__NR_pivot_root] at -> 0xc01405c8
syscall #218 [__NR_mincore] at -> 0xc0122330
syscall #219 [__NR_madvise] at -> 0xc0122088
syscall #220 [__NR_madvise1] at -> 0xc01388c4
syscall #221 [__NR_getdents64] at -> 0xc0137d0c
syscall #222 [__NR_fcntl64] at -> 0xc011a440
syscall #223 [__NR_security] at -> 0xc011a440
syscall #224 [__NR_gettid] at -> 0xc011894c
syscall #225 [__NR_readahead] at -> 0xc01212a4
syscall #226 [__NR_setxattr] at -> 0xc011a440
syscall #227 [__NR_lsetxattr] at -> 0xc011a440
syscall #228 [__NR_fsetxattr] at -> 0xc011a440
syscall #229 [__NR_getxattr] at -> 0xc011a440
syscall #230 [__NR_lgetxattr] at -> 0xc011a440
syscall #231 [__NR_fgetxattr] at -> 0xc011a440
syscall #232 [__NR_listxattr] at -> 0xc011a440
syscall #233 [__NR_llistxattr] at -> 0xc011a440
syscall #234 [__NR_flistxattr] at -> 0xc011a440
syscall #235 [__NR_removexattr] at -> 0xc011a440
syscall #236 [__NR_lremovexattr] at -> 0xc011a440
syscall #237 [__NR_fremovexattr] at -> 0xc011a440
----   end of sys call table dump    ----
```

You can see source code of the module: syscalltable-checker

A sysadmin could execute this module everyday to check if a rootkit has been installed and a system call has changed.

## Changing system calls
Will Continue...

© spinfoo (April 2005)

