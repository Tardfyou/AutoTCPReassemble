import idautils
import idc
import idaapi
import time
import sys
import json
from ida_bytes import get_strlit_contents
from ida_ua import o_void, o_reg, o_mem, o_phrase, o_displ, o_imm
from ida_frame import get_frame_size
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from collections import defaultdict

# 添加Python包路径
sys.path.append('C:\\Users\\balabala\\AppData\\Local\\Programs\\Python\\Python311\\Lib\\site-packages')
import requests
# DeepSeek API 配置
DEEPSEEK_API_KEY = "sk-xxx"
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"

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

# ===== 工具函数 =====
def get_buffer_size(ea: int) -> int:
    """
    获取函数中局部变量的缓冲区大小
    
    Args:
        ea: 地址
        
    Returns:
        缓冲区大小，如无法获取则返回0
    """
    func = idaapi.get_func(ea)
    if func:
        frame_size = get_frame_size(func)
        if frame_size > 0:
            return frame_size
    
    # 尝试从指令中获取大小信息
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea):
        if insn.Op1.type == o_imm:
            return insn.Op1.value
    
    # 尝试从字符串内容获取大小
    str_content = get_strlit_contents(ea, -1, 0)
    if str_content:
        return len(str_content)
    
    return 0

def get_function_by_address(address: int) -> Optional[idaapi.func_t]:
    """
    根据地址获取函数对象
    
    Args:
        address: 指令地址
        
    Returns:
        函数对象，如不存在则返回None
    """
    func = idaapi.get_func(address)
    return func

def get_function_name(address: int) -> str:
    """
    获取函数名称
    
    Args:
        address: 函数地址
        
    Returns:
        函数名称，如不存在则返回空字符串
    """
    return idc.get_func_name(address) or ""

def get_xrefs_to(address: int) -> List[idautils.XrefInfo]:
    """
    获取所有对特定地址的引用
    
    Args:
        address: 目标地址
        
    Returns:
        引用列表
    """
    return list(idautils.XrefsTo(address, 0))

def is_whitelisted(func_name: str) -> bool:
    """
    检查函数名是否在白名单中
    
    Args:
        func_name: 函数名
        
    Returns:
        是否在白名单中
    """
    return func_name in MALWARE_WHITE_LIST

# ===== 漏洞检测实现 =====
def find_sensitive_references() -> List[Dict[str, Any]]:
    """
    查找对敏感函数（如strcpy、sprintf等）的引用
    
    Returns:
        敏感函数引用的列表
    """
    refs = []
    for sensitive in SENSITIVE_FUNCTIONS:
        ea = idc.get_name_ea_simple(sensitive)
        if ea != idc.BADADDR:
            for xref in get_xrefs_to(ea):
                func = get_function_by_address(xref.frm)
                if func:
                    refs.append({
                        'sensitive_func': sensitive,
                        'addr': xref.frm,
                        'func_addr': func.start_ea,
                        'func_name': get_function_name(func.start_ea)
                    })
    return refs

def trace_parameters(func_addr: int) -> bool:
    """
    检查函数调用时是否存在栈溢出风险
    
    Args:
        func_addr: 函数地址
        
    Returns:
        是否存在风险
    """
    func = get_function_by_address(func_addr)
    if not func:
        return False

    local_size = get_buffer_size(func_addr)
    
    for caller_ea in idautils.CodeRefsTo(func.start_ea, 0):
        caller_func = get_function_by_address(caller_ea)
        if caller_func:
            caller_size = get_buffer_size(caller_ea)
            if caller_size > local_size and local_size > 0:
                return True
    
    return False

# ===== 新增：AI分析功能 =====
def analyze_with_ai(vuln_type: str, func_name: str, addr: int, sensitive_func: str, code_snippet: str = "") -> str:
    """
    使用DeepSeek分析漏洞或恶意代码
    
    Args:
        vuln_type: 漏洞或恶意代码类型
        func_name: 涉及的函数名
        addr: 地址
        sensitive_func: 涉及的敏感函数
        code_snippet: 相关代码片段(可选)
        
    Returns:
        分析结果描述
    """
    try:
        prompt = f"""作为安全专家，简洁精确地分析以下漏洞或恶意代码：
类型：{vuln_type}
函数名：{func_name}
地址：0x{addr:x}
相关敏感函数/字符串：{sensitive_func}
代码片段：{code_snippet if code_snippet else '无'}

请用一句话描述该漏洞的成因或恶意代码的具体功能，需包含核心参数，格式如下：
漏洞成因：使用strcpy字符拷贝时，没有做边界检查，且标数组大小只有14B但拷贝数据大小可以最多为100B。
或
具体功能描述：利用system函数调用NC指令创建额外监听端口，端口号为54321。"""

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}"
        }
        
        data = {
            "model": "deepseek-chat",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 100
        }
        
        response = requests.post(DEEPSEEK_API_URL, headers=headers, data=json.dumps(data), timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            analysis = result['choices'][0]['message']['content'].strip()
            
            # 提取关键信息
            if "漏洞成因：" in analysis:
                return analysis.split("漏洞成因：")[1].strip()
            elif "具体功能描述：" in analysis:
                return analysis.split("具体功能描述：")[1].strip()
            else:
                return analysis
        else:
            return f"分析失败：API响应错误 ({response.status_code})"
    
    except Exception as e:
        return f"分析失败：{str(e)}"

def get_disassembly_snippet(addr: int, lines: int = 5) -> str:
    """
    获取指定地址周围的反汇编代码
    
    Args:
        addr: 指令地址
        lines: 获取行数
        
    Returns:
        反汇编代码片段
    """
    snippet = ""
    curr_addr = addr
    
    # 获取前几行
    for _ in range(lines // 2):
        prev_addr = idc.prev_head(curr_addr)
        if prev_addr == idc.BADADDR:
            break
        curr_addr = prev_addr
    
    # 获取代码片段
    for _ in range(lines):
        disasm = idc.generate_disasm_line(curr_addr, 0)
        if disasm:
            snippet += f"0x{curr_addr:x}: {disasm}\n"
        curr_addr = idc.next_head(curr_addr)
        if curr_addr == idc.BADADDR:
            break
    
    return snippet

def report_vulnerability(func_name: str, addr: int, sensitive_func: str, vuln_type: str = "栈溢出"):
    """
    报告检测到的漏洞信息
    
    Args:
        func_name: 检测到漏洞的函数名称
        addr: 漏洞发生的具体地址
        sensitive_func: 触发漏洞的敏感函数名称
        vuln_type: 漏洞类型
    """
    print(f"发现漏洞 - 函数名：{func_name}, 类型：{vuln_type}, 地址：0x{addr:x}, 触发函数：{sensitive_func}")
    
    # 获取代码片段
    code_snippet = get_disassembly_snippet(addr)
    
    # 使用AI分析漏洞成因
    cause = analyze_with_ai(vuln_type, func_name, addr, sensitive_func, code_snippet)
    print(f"漏洞成因：{cause}")

def detect_stack_overflow():
    """
    检测栈溢出漏洞
    """
    sensitive_refs = find_sensitive_references()
    for ref in sensitive_refs:
        if trace_parameters(ref['func_addr']):
            report_vulnerability(
                ref['func_name'], 
                ref['addr'], 
                ref['sensitive_func']
            )

def find_heap_operations() -> List[Dict[str, Any]]:
    """
    查找堆操作相关的函数调用
    
    Returns:
        包含堆操作信息的列表
    """
    heap_ops = []
    
    for heap_func in HEAP_FUNCTIONS:
        ea = idc.get_name_ea_simple(heap_func)
        if ea != idc.BADADDR:
            for xref in get_xrefs_to(ea):
                func = get_function_by_address(xref.frm)
                if func:
                    func_name = get_function_name(func.start_ea)
                    if not func_name.startswith('_') and not is_whitelisted(func_name):
                        heap_ops.append({
                            'func_name': func_name,
                            'addr': xref.frm,
                            'heap_func': heap_func
                        })
    return heap_ops

def detect_heap_overflow():
    """
    检测堆溢出漏洞
    """
    heap_ops = find_heap_operations()
    for op in heap_ops:
        # 分析分配大小是否可控
        if op['heap_func'] in ['.malloc', 'calloc', 'realloc']:
            report_vulnerability(
                op['func_name'], 
                op['addr'], 
                op['heap_func'],
                vuln_type="堆溢出"
            )

def find_free_operations() -> List[Dict[str, Any]]:
    """
    查找所有对free函数的调用
    
    Returns:
        包含free操作信息的列表
    """
    free_ops = []
    free_funcs = ['.free', 'delete', 'operator delete']
    
    for free_func in free_funcs:
        ea = idc.get_name_ea_simple(free_func)
        if ea != idc.BADADDR:
            for xref in get_xrefs_to(ea):
                func = get_function_by_address(xref.frm)
                if func:
                    func_name = get_function_name(func.start_ea)
                    if not func_name.startswith('_') and not is_whitelisted(func_name):
                        free_ops.append({
                            'func_name': func_name,
                            'addr': xref.frm,
                            'func': func,
                            'free_func': free_func
                        })
    return free_ops

def detect_use_after_free():
    """
    检测Use After Free (UAF) 漏洞
    """
    free_ops = find_free_operations()
    for op in free_ops:
        curr_addr = op['addr']
        func_end = op['func'].end_ea
        
        # 检查free指令之后是否可能有对指针的继续使用
        if curr_addr < func_end:
            # 尝试分析free后的指针使用情况
            report_vulnerability(
                op['func_name'], 
                op['addr'], 
                op['free_func'],
                vuln_type="Use After Free"
            )

def detect_double_free():
    """
    检测Double Free漏洞
    """
    free_ops = find_free_operations()
    # 按函数分组统计free调用
    free_counts = defaultdict(list)
    for op in free_ops:
        free_counts[op['func_name']].append(op)
    
    # 报告可能的Double Free漏洞
    for func_name, ops in free_counts.items():
        if len(ops) > 1:
            # 多次调用free的函数可能存在Double Free风险
            report_vulnerability(
                func_name,
                ops[0]['addr'],
                ops[0]['free_func'],
                vuln_type="Double Free"
            )

def detect_format_string():
    """
    检测格式字符串漏洞
    """
    format_funcs = ['printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf']
    
    for format_func in format_funcs:
        ea = idc.get_name_ea_simple(format_func)
        if ea != idc.BADADDR:
            for xref in get_xrefs_to(ea):
                func = get_function_by_address(xref.frm)
                if func:
                    func_name = get_function_name(func.start_ea)
                    if not func_name.startswith('_') and not is_whitelisted(func_name):
                        # 简单检测: 如果参数可能是用户输入，则可能存在格式字符串漏洞
                        report_vulnerability(
                            func_name,
                            xref.frm,
                            format_func,
                            vuln_type="格式字符串漏洞"
                        )

def detect_integer_overflow():
    """
    检测整数溢出漏洞
    """
    arithmetic_ops = []
    
    # 遍历所有函数
    for func_ea in idautils.Functions():
        func_name = get_function_name(func_ea)
        if func_name.startswith('_') or is_whitelisted(func_name):
            continue
            
        # 查找存在整数运算且结果用于内存分配的情况
        for heap_func in HEAP_FUNCTIONS:
            heap_ea = idc.get_name_ea_simple(heap_func)
            if heap_ea != idc.BADADDR:
                for xref in get_xrefs_to(heap_ea):
                    if get_function_by_address(xref.frm) and get_function_name(get_function_by_address(xref.frm).start_ea) == func_name:
                        report_vulnerability(
                            func_name,
                            xref.frm,
                            heap_func,
                            vuln_type="整数溢出"
                        )

def scan_vulnerabilities():
    """
    执行所有软件漏洞检测
    """
    print("开始软件漏洞检测...")
    detect_stack_overflow()      # 栈溢出
    detect_heap_overflow()       # 堆溢出
    detect_use_after_free()      # Use After Free
    detect_double_free()         # Double Free
    detect_format_string()       # 格式字符串漏洞(新增)
    detect_integer_overflow()    # 整数溢出(新增)
    print("软件漏洞检测完成。")
    print("--------------------------------")

# ===== 恶意代码检测实现 =====
def find_signature_matches(signatures: List[str]) -> List[Tuple[str, int, str]]:
    """
    查找与指定签名匹配的代码位置
    
    Args:
        signatures: 签名列表，用于在代码中搜索匹配项
        
    Returns:
        匹配结果列表，每个元素包含函数名、地址和匹配的证据
    """
    matches = []
    
    # 1. 搜索字符串引用
    for ea in idautils.Strings():
        str_val = str(ea).lower()
        
        for sig in signatures:
            if sig.lower() in str_val:
                for xref in get_xrefs_to(ea.ea):
                    func = get_function_by_address(xref.frm)
                    if not func:
                        continue
                    func_name = get_function_name(func.start_ea)
                    
                    if is_whitelisted(func_name):
                        continue
                     
                    matches.append((func_name, xref.frm, str_val))

    # 2. 搜索函数引用
    for sig in signatures:
        ea = idc.get_name_ea_simple(sig)
        if ea != idc.BADADDR:
            refs_processed = set()
            refs_to_process = set(ref.frm for ref in get_xrefs_to(ea))
            
            while refs_to_process:
                curr_ea = refs_to_process.pop()
                if curr_ea in refs_processed:
                    continue
                    
                refs_processed.add(curr_ea)
                func = get_function_by_address(curr_ea)
                if not func:
                    continue
                    
                func_name = get_function_name(func.start_ea)
                
                if is_whitelisted(func_name):
                    continue
                    
                matches.append((func_name, curr_ea, sig))
                
                # 递归搜索引用该函数的其他引用
                for ref in get_xrefs_to(func.start_ea):
                    caller_func = get_function_by_address(ref.frm)
                    if caller_func:
                        caller_name = get_function_name(caller_func.start_ea)
                        if not is_whitelisted(caller_name):
                            refs_to_process.add(ref.frm)
    
    return matches

def report_malicious(malware_type: str, func_name: str, addr: int, evidence: str):
    """
    通用恶意代码报告函数
    
    Args:
        malware_type: 恶意代码类型
        func_name: 检测到恶意代码的函数名称
        addr: 恶意代码发生的具体地址
        evidence: 支持恶意检测的证据
    """
    print(f"发现恶意代码 - 函数名：{func_name}, 类型：{malware_type}, 地址：0x{addr:x}, 证据：{evidence}")
    
    # 获取代码片段
    code_snippet = get_disassembly_snippet(addr)
    
    # 使用AI分析恶意代码功能
    function_desc = analyze_with_ai(malware_type, func_name, addr, evidence, code_snippet)
    print(f"具体功能描述：{function_desc}")

def detect_malicious_signature(malware_type: str, signatures: List[str]):
    """
    通用恶意行为检测函数
    
    Args:
        malware_type: 恶意代码类型
        signatures: 签名列表
    """
    matches = find_signature_matches(signatures)
    for func_name, addr, evidence in matches:
        report_malicious(malware_type, func_name, addr, evidence)

def scan_malicious_code():
    """
    执行所有恶意代码检测
    """
    print("开始恶意代码检测...")
    
    # 系统文件删除与修改
    detect_malicious_signature("系统文件删除与修改", MALWARE_BLACK_LIST["system_file_deletion"])
    
    # 权限危险操作
    detect_malicious_signature("权限提升", MALWARE_BLACK_LIST["suspicious_permission_change"])
    
    # 恶意代码执行
    detect_malicious_signature("恶意代码执行", MALWARE_BLACK_LIST["code_execution"])
    
    # 后门程序
    detect_malicious_signature("后门程序", MALWARE_BLACK_LIST["open_backdoor"])
    
    # 僵尸进程
    detect_malicious_signature("僵尸进程", MALWARE_BLACK_LIST["create_zombie_process"])
    
    # 禁用系统保护
    detect_malicious_signature("禁用系统保护", MALWARE_BLACK_LIST["disable_protection"])
    
    # 数据窃取行为(新增)
    detect_malicious_signature("数据窃取", MALWARE_BLACK_LIST["data_exfiltration"])
    
    # 加密勒索行为(新增)
    detect_malicious_signature("勒索软件行为", MALWARE_BLACK_LIST["ransomware"])
    
    print("恶意代码检测完成。")

def generate_summary_report():
    """
    生成检测摘要报告，总结发现的漏洞和恶意代码
    """
    print("\n===== 扫描摘要报告 =====")
    print("扫描对象：", idc.get_input_file_path())
    print("扫描时间：", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    print("请查看上方详细信息了解所有发现的问题。")
    print("=======================\n")

def run_plugin():
    """
    插件主流程
    """
    print("================================")
    print("IDA Pro 漏洞与恶意代码分析工具")
    print("版本: 3.0 (增强AI分析)")
    print("================================")
    
    # 执行漏洞检测
    scan_vulnerabilities()
    
    # 执行恶意代码检测
    scan_malicious_code()
    
    # 生成摘要报告
    generate_summary_report()
    
    print("================================")
    print("分析完成！")

# 插件入口
if __name__ == '__main__':
    run_plugin()