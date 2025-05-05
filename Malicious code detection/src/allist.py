# ===== 恶意代码检测规则集 =====
# 恶意行为的简单签名，基于关键函数或可疑字符串（仅Linux系统）
MALWARE_BLACK_LIST = {
    "system_file_deletion": [
        "remove", "unlink", 
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/etc/sudoers", "/var/log", "rm -rf",
        "shred", "truncate"
    ],
    "open_backdoor": [
        "nc -l", "netcat", "socket", "bind", 
        "listen", "popen", "/bin/sh",
        "reverse shell", "connect back", "backdoor",
        "/dev/tcp", "/dev/udp"
    ],
    "create_zombie_process": [
        "fork", "sigchld", "waitpid",
        "SIGCHLD", "SA_NOCLDWAIT"
    ],
    "disable_protection": [
        "setenforce", "disable selinux", "selinux", "sysctl",
        "iptables -F", "mount -o remount",
        "/proc/sys/kernel/randomize_va_space",
        "/etc/selinux/config"
    ],
    "suspicious_permission_change": [  
        "chmod", "chown", "chgrp",
        "/etc/passwd", "/etc/shadow", "/etc/group",
        "/etc/sudoers",
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/tmp",
        "0777", "777", "01777", "1777", "04777", "4777",
        "02777", "2777", "4755", "2755",
        "setuid", "setgid", "umask 0"
    ],
    "code_execution": [
        ".sh", ".py", ".c", ".cpp", ".php", 
        "popen", "eval", "shellcode"
    ],
    # 新增: 数据窃取行为检测
    "data_exfiltration": [
        "curl", "wget", "ftp", "scp", "rsync",
        "base64", "xxd", "hexdump",
        "/etc/passwd", "/etc/shadow", "/home",
        "/var/log", "/var/www", "~/.ssh",
        "id_rsa", "id_dsa", ".bash_history"
    ],
    # 新增: 加密勒索行为检测
    "ransomware": [
        "encrypt", "ransom", "bitcoin", "monero",
        ".encrypt", ".locked", ".crypted", ".pay",
        "README.txt", "DECRYPT.txt",
        "openssl enc", "aes-256-cbc"
    ]
}

# 白名单：标准库和系统函数
MALWARE_WHITE_LIST = {
    # 文件操作相关
    "remove", ".remove", 
    "fork",
    # 网络相关
    "listen", ".listen",
    "bind", ".bind",
    "socket", ".socket",
    # 系统相关
    "system", ".system",
    # 其他常见库函数
    "popen", ".popen",
    "exec", ".exec",
    "chmod", ".chmod",
    "chown", ".chown",
    # 常见函数名
    "main", "__libc_start_main", "_start"
}

# 安全敏感函数列表
SENSITIVE_FUNCTIONS = [
    'strcpy', 'sprintf', 'gets', 'memcpy', '.strncpy',
    'strcat', '.strcat', 'scanf', 'fscanf', 'sscanf',
    'getc', 'fgetc', 'fgets', 'read'
]

# 堆操作相关函数
HEAP_FUNCTIONS = ['.malloc', 'calloc', 'realloc', '.new', 'operator new']
