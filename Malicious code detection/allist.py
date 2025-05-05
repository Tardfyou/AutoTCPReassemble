# 恶意行为的简单签名，基于关键函数或可疑字符串（仅Linux系统）
MALWARE_BLACK_LIST = {
    "system_file_deletion": [
        "remove", "unlink", 
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/etc/sudoers", "/var/log", "rm -rf",
        "shred", "truncate",
        "dd if=/dev/zero of=",  # 使用 dd 命令覆盖文件
        "wipe", "erase"  # 其他可能的文件擦除工具
    ],
    "open_backdoor": [
        "nc -l", "netcat", "socket", "bind", 
        "listen", "popen", "/bin/sh",
        "reverse shell", "connect back", "backdoor",
        "/dev/tcp", "/dev/udp",
        "ssh -R", "ssh -L",  # 利用 SSH 隧道创建后门
        "socat", "ncat"  # 其他网络工具可能用于后门
    ],
    "create_zombie_process": [
        "fork", "sigchld", "waitpid",
        "SIGCHLD", "SA_NOCLDWAIT",
        "nohup", "disown"  # 防止子进程被父进程回收
    ],
    "disable_protection": [
        "setenforce", "disable selinux", "selinux", "sysctl",
        "iptables -F", "mount -o remount",
        "/proc/sys/kernel/randomize_va_space",
        "/etc/selinux/config",
        "echo 0 > /proc/sys/kernel/exec-shield",  # 禁用 exec-shield
        "echo 0 > /proc/sys/vm/mmap_min_addr"  # 降低内存保护
    ],
    "suspicious_permission_change": [  
        "chmod", "chown", "chgrp",
        "/etc/passwd", "/etc/shadow", "/etc/group", # 敏感文件的权限修改
        "/etc/sudoers",
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",  # 系统关键目录的权限修改
        "/tmp", # /tmp 目录滥用, 可能用于创建临时可执行文件
        "0777", "777",  # 过于宽松的权限
        "01777", "1777", # 包含 sticky bit 的宽松权限
        "04777", "4777",  # 包含 setuid 的宽松权限
        "02777", "2777",  # 包含 setgid 的宽松权限
        "4755", "2755", # 可能用于提权的组合
        "setuid", "setgid",  # setuid/setgid 程序
        "umask 0", # 完全取消权限掩码, 使后续创建的文件/目录具有最大权限
        "chattr +i",  # 设置文件不可修改
        "chattr -i"   # 移除文件不可修改属性
    ],
    "code_execution": [
        ".sh", ".py", ".c", ".cpp", ".php", 
        "popen", "eval", "shellcode",
        "eval base64_decode(",  # 可能用于执行 Base64 编码的恶意代码
        "system(", ".system",  # 直接调用系统命令
        "execve", "execl", "execv"  # 替换进程映像
    ]
}

# 白名单：标准库和系统函数
MALWARE_WHITE_LIST = {
    # 文件操作相关
    "remove", ".remove", 
    "fork",
    "fwrite", "fread", "fprintf", "fscanf",  # 文件读写相关
    # 网络相关
    "listen", ".listen",
    "bind", ".bind",
    "socket", ".socket",
    "accept", "connect", "send", "recv",  # 网络通信相关
    # 系统相关
    "system", ".system",
    "execve", "execl", "execv",  # 进程执行相关
    # 其他常见库函数
    "popen", ".popen",
    "chmod", ".chmod",
    "chown", ".chown"
}

SENSITIVE_FUNCTIONS = ['strcpy', 'sprintf', 'gets', 'memcpy', '.strncpy', 'strcat', 'vsprintf']

HEAP_FUNCTIONS = ['.malloc', 'calloc', 'realloc', 'free', 'alloca']  # 添加更多堆相关函数