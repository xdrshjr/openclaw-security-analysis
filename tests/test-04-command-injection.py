#!/usr/bin/env python3
"""
OpenClaw 代码执行安全测试 - PoC 1: 命令注入绕过
Test Case: test-04-command-injection.py
Category: Command Injection
Severity: High

分析发现：exec-safety.ts中的isSafeExecutableValue()函数存在绕过可能，
通过精心构造的shell元字符组合可能绕过安全检查。
"""

import re
import subprocess
import sys

def test_shell_metachar_bypass():
    """
    测试shell元字符检测绕过
    
    漏洞分析：
    - SHELL_METACHARS = /[;&|`$<>]/
    - 存在逻辑绕过可能：使用$()替代反引号
    - 使用 Unicode 同形字符可能绕过检测
    """
    
    # 模拟OpenClaw的isSafeExecutableValue函数
    SHELL_METACHARS = re.compile(r'[;&|`$<>]')
    CONTROL_CHARS = re.compile(r'[\r\n]')
    QUOTE_CHARS = re.compile(r'["\']')
    BARE_NAME_PATTERN = re.compile(r'^[A-Za-z0-9._+-]+$')
    
    def is_safe_executable_value(value):
        if not value:
            return False
        trimmed = value.strip()
        if not trimmed:
            return False
        if '\0' in trimmed:
            return False
        if CONTROL_CHARS.search(trimmed):
            return False
        if SHELL_METACHARS.search(trimmed):
            return False
        if QUOTE_CHARS.search(trimmed):
            return False
        return BARE_NAME_PATTERN.match(trimmed) is not None
    
    # 测试用例
    test_cases = [
        # (input, expected_safe, description)
        ("ls -la", True, "正常命令"),
        ("cat file.txt", True, "正常命令带参数"),
        ("ls; rm -rf /", False, "明显的命令分隔符"),
        ("`whoami`", False, "反引号命令替换"),
        ("$(whoami)", False, "$()命令替换"),
        # 绕过尝试
        ("ls\x00;id", True, "NULL字节截断可能绕过"),
        ("ls…", True, "Unicode同形字符"),
        ("ls\u2028id", True, "Unicode行分隔符"),
    ]
    
    print("=" * 60)
    print("测试: Shell元字符检测绕过")
    print("=" * 60)
    
    bypass_found = []
    for value, expected_safe, desc in test_cases:
        is_safe = is_safe_executable_value(value)
        status = "✓" if is_safe == expected_safe else "✗ BYPASS"
        if is_safe != expected_safe:
            bypass_found.append((value, desc))
        print(f"{status} [{desc}]")
        print(f"    Input: {repr(value)}")
        print(f"    Detected as safe: {is_safe}")
        print()
    
    return bypass_found


def test_dangerous_env_injection():
    """
    测试危险环境变量注入
    
    漏洞分析：
    - bash-tools.exec.ts中的DANGEROUS_HOST_ENV_VARS检查
    - 可能通过大小写绕过或变量名变种绕过
    """
    
    DANGEROUS_HOST_ENV_VARS = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
        "NODE_OPTIONS", "NODE_PATH",
        "PYTHONPATH", "PYTHONHOME",
        "BASH_ENV", "ENV",
    }
    DANGEROUS_HOST_ENV_PREFIXES = ["DYLD_", "LD_"]
    
    def validate_host_env_original(env):
        """原始验证逻辑"""
        for key in env.keys():
            upper_key = key.upper()
            if any(upper_key.startswith(prefix) for prefix in DANGEROUS_HOST_ENV_PREFIXES):
                raise ValueError(f"Forbidden: {key}")
            if upper_key in DANGEROUS_HOST_ENV_VARS:
                raise ValueError(f"Forbidden: {key}")
    
    # 绕过尝试
    test_envs = [
        ({"LD_PRELOAD": "/evil.so"}, "标准危险变量", True),
        ({"ld_preload": "/evil.so"}, "小写变量名", True),  # 应该被阻止
        ({"LD_PRELOAD_": "/evil.so"}, "变种变量名", False),  # 可能绕过
        ({"MY_LD_PRELOAD": "/evil.so"}, "前缀注入", False),  # 可能绕过
        ({"PATH": "/evil/bin"}, "PATH修改", True),  # 应该被阻止
    ]
    
    print("=" * 60)
    print("测试: 危险环境变量注入绕过")
    print("=" * 60)
    
    bypass_found = []
    for env, desc, should_block in test_envs:
        try:
            validate_host_env_original(env)
            blocked = False
        except ValueError:
            blocked = True
        
        if blocked != should_block:
            bypass_found.append((env, desc))
            status = "✗ BYPASS"
        else:
            status = "✓"
        
        print(f"{status} [{desc}]")
        print(f"    Env: {env}")
        print(f"    Blocked: {blocked}, Expected: {should_block}")
        print()
    
    return bypass_found


def test_command_chain_injection():
    """
    测试命令链注入
    
    漏洞分析：
    - splitCommandChain函数可能无法正确解析复杂命令链
    - && || ; 组合可能产生非预期行为
    """
    
    print("=" * 60)
    print("测试: 命令链注入")
    print("=" * 60)
    
    # 复杂命令链测试
    complex_commands = [
        "git status && git add . && git commit -m 'test'",
        "false || echo 'fallback'",
        "cmd1; cmd2; cmd3",
        "echo '&&' && evil_cmd",  # 引号内与引号外
        "echo 'test'\nevil_cmd",  # 换行符注入
    ]
    
    for cmd in complex_commands:
        print(f"Command: {cmd[:50]}...")
        print(f"  Length: {len(cmd)}")
        # 检查是否包含命令链操作符
        has_chain = any(op in cmd for op in ['&&', '||', ';'])
        print(f"  Has chain operator: {has_chain}")
        print()
    
    return []


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("OpenClaw 代码执行安全测试套件")
    print("=" * 70 + "\n")
    
    bypasses = []
    bypasses.extend(test_shell_metachar_bypass())
    bypasses.extend(test_dangerous_env_injection())
    bypasses.extend(test_command_chain_injection())
    
    print("\n" + "=" * 70)
    print("测试总结")
    print("=" * 70)
    if bypasses:
        print(f"[!] 发现 {len(bypasses)} 个潜在绕过:")
        for b in bypasses:
            print(f"    - {b[1]}: {b[0]}")
    else:
        print("[✓] 未发现明显绕过")
    print()
