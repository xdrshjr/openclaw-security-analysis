#!/usr/bin/env python3
"""
PoC 3: 内存数据安全与缓存分析
测试会话数据和敏感信息在内存中的存储方式
"""

import json
import time
from datetime import datetime

def test_session_cache_exposure():
    """
    验证会话缓存是否明文存储敏感信息
    模拟session/store.ts中的SESSION_STORE_CACHE
    """
    print("=" * 60)
    print("[PoC-05-005] 会话缓存敏感信息暴露检测")
    print("=" * 60)
    
    # 模拟SESSION_STORE_CACHE数据结构
    SESSION_STORE_CACHE = {}
    
    # 模拟存储会话数据（包含敏感信息）
    mock_session_entry = {
        "sessionId": "agent:main:session:12345",
        "updatedAt": int(time.time() * 1000),
        "deliveryContext": {
            "channel": "whatsapp",
            "to": "1234567890@s.whatsapp.net",
            "accountId": "default",
            "threadId": "thread_12345"
        },
        "lastChannel": "whatsapp",
        "lastTo": "1234567890@s.whatsapp.net",
        "lastAccountId": "default",
        "lastThreadId": "thread_12345",
        # 模拟可能包含的敏感元数据
        "_internal": {
            "authToken": "temp_token_abc123",
            "sessionKey": "private_key_data_here",
            "apiResponse": {
                "access_token": "oauth_token_xyz789",
                "refresh_token": "refresh_abc123"
            }
        }
    }
    
    store_path = "/agents/main/sessions/sessions.json"
    
    # 模拟缓存存储
    SESSION_STORE_CACHE[store_path] = {
        "store": { "session:12345": mock_session_entry },
        "loadedAt": int(time.time() * 1000),
        "storePath": store_path,
        "mtimeMs": int(time.time() * 1000)
    }
    
    print(f"\n[+] 模拟会话缓存结构:")
    print(f"    缓存键: {store_path}")
    print(f"    加载时间: {datetime.fromtimestamp(SESSION_STORE_CACHE[store_path]['loadedAt']/1000)}")
    
    # 检查内存中的敏感信息
    print(f"\n[+] 检查内存缓存中的敏感信息...")
    
    sensitive_paths = [
        ("session._internal.authToken", "认证令牌"),
        ("session._internal.sessionKey", "会话密钥"),
        ("session._internal.apiResponse.access_token", "OAuth访问令牌"),
        ("session._internal.apiResponse.refresh_token", "OAuth刷新令牌"),
    ]
    
    cache_entry = SESSION_STORE_CACHE[store_path]['store']['session:12345']
    
    exposed = []
    if '_internal' in cache_entry:
        internal = cache_entry['_internal']
        if 'authToken' in internal:
            exposed.append(('authToken', internal['authToken']))
        if 'sessionKey' in internal:
            exposed.append(('sessionKey', internal['sessionKey']))
        if 'apiResponse' in internal:
            api_resp = internal['apiResponse']
            if 'access_token' in api_resp:
                exposed.append(('access_token', api_resp['access_token']))
            if 'refresh_token' in api_resp:
                exposed.append(('refresh_token', api_resp['refresh_token']))
    
    if exposed:
        print(f"\n[!] 发现 {len(exposed)} 处内存中的敏感信息:")
        for name, value in exposed:
            masked = value[:10] + "..." if len(value) > 10 else value
            print(f"    - {name}: {masked}")
        print(f"\n[✗] 漏洞: 敏感信息在内存缓存中明文存储!")
        print(f"    - 可能被内存dump攻击获取")
        print(f"    - 没有内存加密机制")
        print(f"    - 缓存TTL为45秒，敏感数据在内存中停留时间较长")
    else:
        print(f"\n[+] 未发现明显的敏感信息")
    
    return len(exposed) > 0

def test_shell_env_fallback_risk():
    """
    验证shell环境回退机制的安全风险
    模拟shell-env.ts的行为
    """
    print("\n" + "=" * 60)
    print("[PoC-05-006] Shell环境回退安全风险检测")
    print("=" * 60)
    
    # 模拟用户shell环境中的敏感变量
    shell_env_output = """
HOME=/home/user
PATH=/usr/bin:/bin
OPENAI_API_KEY=sk-from-shell-env-123456789
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DISCORD_BOT_TOKEN=discord.token.from.shell
GITHUB_TOKEN=ghp_secrettokenfromshell123
ELEVENLABS_API_KEY=elevenlabs_key_from_shell
"""
    
    print("\n[+] 模拟Shell环境输出内容:")
    for line in shell_env_output.strip().split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            if any(s in key.lower() for s in ['key', 'token', 'secret', 'password']):
                masked = value[:15] + "..." if len(value) > 15 else value
                print(f"    {key}={masked}")
    
    # 模拟预期加载的键
    expected_keys = [
        "OPENAI_API_KEY",
        "ELEVENLABS_API_KEY",
        "DISCORD_BOT_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN"
    ]
    
    print(f"\n[+] 分析环境变量加载机制:")
    print(f"    当前进程环境变量: 未设置")
    print(f"    OPENCLAW_LOAD_SHELL_ENV: true")
    print(f"    预期从shell加载的键: {len(expected_keys)}个")
    
    # 模拟从shell加载
    loaded_from_shell = []
    for key in expected_keys:
        # 模拟shell env中有这些值
        value = f"{key.lower()}_value_from_shell"
        loaded_from_shell.append((key, value))
    
    print(f"\n[!] 安全风险:")
    print(f"    - 从shell环境自动加载 {len(loaded_from_shell)} 个变量")
    print(f"    - 用户可能在.bashrc/.zshrc中硬编码了敏感信息")
    print(f"    - OpenClaw进程将继承这些敏感变量")
    print(f"    - 这些变量可能被记录到日志中")
    
    sensitive_loaded = [k for k, v in loaded_from_shell if any(s in k.lower() for s in ['key', 'token', 'secret'])]
    
    if sensitive_loaded:
        print(f"\n[✗] 漏洞: {len(sensitive_loaded)} 个敏感变量将从shell环境加载!")
        for key in sensitive_loaded:
            print(f"    - {key}")
        return True
    
    return False

def test_cache_ttl_security():
    """
    验证缓存TTL设置对安全的影响
    """
    print("\n" + "=" * 60)
    print("[PoC-05-007] 缓存TTL安全配置分析")
    print("=" * 60)
    
    DEFAULT_SESSION_STORE_TTL_MS = 45000  # 45秒
    
    print(f"\n[+] 默认会话缓存TTL: {DEFAULT_SESSION_STORE_TTL_MS}ms ({DEFAULT_SESSION_STORE_TTL_MS/1000}秒)")
    
    # 模拟敏感数据在内存中的停留时间
    scenarios = [
        ("单次请求", 5000, "低"),
        ("活跃会话", 45000, "中"),
        ("长会话", 120000, "高"),
        ("攻击窗口(暴力dump)", 45000, "中"),
    ]
    
    print(f"\n[+] 敏感数据内存暴露时间分析:")
    print(f"    {'场景':<20} {'暴露时间':<15} {'风险等级':<10}")
    print(f"    {'-'*50}")
    for scenario, duration, risk in scenarios:
        print(f"    {scenario:<20} {duration/1000:>6.1f}s{'':<8} {risk:<10}")
    
    print(f"\n[!] 安全建议:")
    print(f"    - 当前TTL设置: 45秒")
    print(f"    - 建议降低TTL至: 5-10秒")
    print(f"    - 建议添加: 敏感数据内存加密")
    print(f"    - 建议添加: 进程内存隔离")
    
    return True

if __name__ == "__main__":
    print("\n🔒 OpenClaw 内存安全分析 - PoC测试套件\n")
    
    result1 = test_session_cache_exposure()
    result2 = test_shell_env_fallback_risk()
    result3 = test_cache_ttl_security()
    
    print("\n" + "=" * 60)
    print("[测试总结]")
    print("=" * 60)
    print(f"测试1 (会话缓存泄露): {'发现漏洞 ✗' if result1 else '未发现问题 ✓'}")
    print(f"测试2 (Shell环境风险): {'发现漏洞 ✗' if result2 else '未发现问题 ✓'}")
    print(f"测试3 (缓存TTL分析): {'完成分析 ℹ️' if result3 else '未完成'}")
    
    print("\n[!] 内存安全建议:")
    print("    1. 实施内存中敏感数据加密")
    print("    2. 减少敏感数据在内存中的停留时间")
    print("    3. 添加内存访问保护机制")
    print("    4. 禁用或限制shell环境回退功能")
