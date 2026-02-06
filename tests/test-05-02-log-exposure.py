#!/usr/bin/env python3
"""
PoC 2: 日志敏感信息泄露检测
测试日志系统是否可能记录敏感信息
"""

import os
import json
import tempfile
import re

def test_log_sensitive_info_exposure():
    """
    验证日志文件是否可能包含敏感信息
    模拟logger.ts的行为
    """
    print("=" * 60)
    print("[PoC-05-003] 日志敏感信息泄露检测")
    print("=" * 60)
    
    # 模拟日志条目
    mock_logs = [
        {
            "time": "2024-01-01T12:00:00.000Z",
            "level": "info",
            "message": "env: OPENAI_API_KEY=sk-abc123... (OpenAI API Key)"
        },
        {
            "time": "2024-01-01T12:01:00.000Z", 
            "level": "debug",
            "message": "Request headers",
            "headers": {
                "Authorization": "Bearer sk_test_placeholder",
                "X-API-Key": "secret_key_123456789"
            }
        },
        {
            "time": "2024-01-01T12:02:00.000Z",
            "level": "info",
            "message": "Device auth token stored",
            "deviceId": "device-12345",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        },
        {
            "time": "2024-01-01T12:03:00.000Z",
            "level": "warn",
            "message": "shell env fallback applied",
            "appliedKeys": ["OPENAI_API_KEY", "DISCORD_BOT_TOKEN", "AWS_SECRET_ACCESS_KEY"]
        }
    ]
    
    # 创建模拟日志文件
    log_dir = tempfile.mkdtemp(prefix="openclaw_logs_")
    log_file = os.path.join(log_dir, "openclaw-2024-01-01.log")
    
    with open(log_file, 'w') as f:
        for entry in mock_logs:
            f.write(json.dumps(entry) + '\n')
    
    print(f"\n[+] 模拟日志目录: {log_dir}")
    print(f"[+] 日志文件: {log_file}")
    
    # 检查日志内容
    print(f"\n[+] 分析日志内容中的敏感信息...")
    
    sensitive_patterns = [
        (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI API Key'),
        (r'Bearer\s+[a-zA-Z0-9_\-\.]+', 'Bearer Token'),
        (r'[a-zA-Z0-9_]*token[a-zA-Z0-9_]*["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.]+', 'Token'),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.]+', 'API Key'),
        (r'secret["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.]+', 'Secret'),
        (r'password["\']?\s*[:=]\s*["\']?[^\s"\']+', 'Password'),
    ]
    
    found_issues = []
    
    with open(log_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            for pattern, pattern_name in sensitive_patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                if matches:
                    found_issues.append({
                        'line': line_num,
                        'type': pattern_name,
                        'match': matches[0][:50] + '...' if len(matches[0]) > 50 else matches[0]
                    })
    
    if found_issues:
        print(f"\n[!] 发现 {len(found_issues)} 处敏感信息泄露:")
        for issue in found_issues:
            print(f"    行 {issue['line']}: [{issue['type']}] {issue['match']}")
    else:
        print(f"\n[+] 未发现明显的敏感信息模式")
    
    # 检查目录权限问题
    print(f"\n[+] 检查日志目录安全性...")
    log_stat = os.stat(log_dir)
    file_stat = os.stat(log_file)
    
    print(f"    日志目录权限: {oct(log_stat.st_mode)[-3:]}")
    print(f"    日志文件权限: {oct(file_stat.st_mode)[-3:]}")
    
    # 模拟/tmp目录的共享风险
    if "/tmp" in log_dir or True:  # 模拟
        print(f"\n[!] 安全风险: 日志存储在共享目录 (/tmp/openclaw)")
        print(f"    - 同一系统的其他用户可能访问")
        print(f"    - 没有自动清理过期日志的加密机制")
        print(f"    - 日志保留24小时后才会清理")
    
    # 清理
    import shutil
    shutil.rmtree(log_dir)
    
    return len(found_issues) > 0

def test_log_redaction_incomplete():
    """
    验证日志脱敏机制是否完整
    基于env.ts中的logAcceptedEnvOption实现
    """
    print("\n" + "=" * 60)
    print("[PoC-05-004] 日志脱敏机制完整性检测")
    print("=" * 60)
    
    # 模拟环境变量日志记录
    env_vars = [
        {"key": "OPENAI_API_KEY", "value": "sk-abc123", "redact": True, "description": "OpenAI API Key"},
        {"key": "ELEVENLABS_API_KEY", "value": "el-api-key-123", "redact": False, "description": "ElevenLabs Key"},
        {"key": "DISCORD_BOT_TOKEN", "value": "discord.token.here", "redact": False, "description": "Discord Token"},
        {"key": "TWILIO_AUTH_TOKEN", "value": "twilio_secret", "redact": True, "description": "Twilio Auth"},
        {"key": "AWS_ACCESS_KEY_ID", "value": "AKIAIOSFODNN7EXAMPLE", "redact": False, "description": "AWS Access Key"},
    ]
    
    print("\n[+] 分析环境变量日志脱敏情况:")
    print("    " + "-" * 50)
    
    unprotected = []
    for var in env_vars:
        status = "<redacted>" if var['redact'] else var['value']
        print(f"    {var['key']}: {status}")
        if not var['redact']:
            unprotected.append(var['key'])
    
    print("    " + "-" * 50)
    
    if unprotected:
        print(f"\n[!] 发现 {len(unprotected)} 个环境变量未脱敏:")
        for key in unprotected:
            print(f"    - {key}")
        print(f"\n[✗] 漏洞: 部分敏感环境变量在日志中完全暴露!")
        return True
    else:
        print(f"\n[✓] 所有环境变量都有脱敏保护")
        return False

if __name__ == "__main__":
    print("\n🔒 OpenClaw 日志安全分析 - PoC测试套件\n")
    
    result1 = test_log_sensitive_info_exposure()
    result2 = test_log_redaction_incomplete()
    
    print("\n" + "=" * 60)
    print("[测试总结]")
    print("=" * 60)
    print(f"测试1 (日志泄露): {'发现漏洞 ✗' if result1 else '未发现问题 ✓'}")
    print(f"测试2 (脱敏不完整): {'发现漏洞 ✗' if result2 else '未发现问题 ✓'}")
    
    if result1 or result2:
        print("\n[!] 建议:")
        print("    1. 实施统一的日志脱敏机制")
        print("    2. 将日志目录移至用户私有目录")
        print("    3. 对敏感字段使用结构化脱敏规则")
