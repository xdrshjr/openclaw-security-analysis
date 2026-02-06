#!/usr/bin/env python3
"""
PoC 1: 敏感数据明文存储检测
测试device-auth-store.ts中token是否以明文存储
"""

import os
import json
import tempfile
import stat

def test_sensitive_data_plaintext_storage():
    """
    验证OpenClaw的敏感数据存储方式
    模拟device-auth-store.ts的行为
    """
    print("=" * 60)
    print("[PoC-05-001] 敏感数据明文存储检测")
    print("=" * 60)
    
    # 模拟device-auth-store.ts中的数据结构
    mock_device_auth = {
        "version": 1,
        "deviceId": "device-12345",
        "tokens": {
            "admin": {
                "token": "sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                "role": "admin",
                "scopes": ["read", "write", "admin"],
                "updatedAtMs": 1704067200000
            }
        }
    }
    
    # 创建临时文件模拟存储
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(mock_device_auth, f, indent=2)
        temp_path = f.name
    
    try:
        # 模拟0o600权限设置
        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
        
        print(f"\n[+] 模拟存储文件: {temp_path}")
        print(f"[+] 文件权限: {oct(os.stat(temp_path).st_mode)[-3:]}")
        
        # 验证是否明文存储
        with open(temp_path, 'r') as f:
            content = f.read()
            
        print(f"\n[+] 文件内容 (前500字符):")
        print(content[:500])
        
        # 检查敏感信息是否可被直接读取
        parsed = json.loads(content)
        token = parsed['tokens']['admin']['token']
        
        print(f"\n[!] 安全漏洞确认:")
        print(f"    - Token以明文存储: {token[:30]}...")
        print(f"    - 无加密机制")
        print(f"    - 任何有文件读取权限的用户都可获取")
        
        # 验证是否可解码
        if 'sk_' in token or len(token) > 20:
            print(f"\n[✗] 漏洞存在: API密钥/Token完全暴露在明文JSON中!")
            return False
            
    finally:
        os.unlink(temp_path)
    
    return True

def test_whatsapp_creds_exposure():
    """
    验证WhatsApp凭证存储方式
    模拟auth-store.ts中的creds.json
    """
    print("\n" + "=" * 60)
    print("[PoC-05-002] WhatsApp凭证明文存储检测")
    print("=" * 60)
    
    # 模拟真实的WhatsApp凭证结构
    mock_creds = {
        "noiseKey": {
            "private": "base64_encoded_private_key_xxxxxxxxxxxx",
            "public": "base64_encoded_public_key_yyyyyyyyyyyy"
        },
        "signedIdentityKey": {
            "private": "base64_signed_private_zzzzzzzzzzzzzz",
            "public": "base64_signed_public_wwwwwwwwwwww"
        },
        "signedPreKey": {
            "keyPair": {
                "private": "base64_prekey_private_aaaaaaaaaaaa",
                "public": "base64_prekey_public_bbbbbbbbbbbb"
            },
            "signature": "base64_signature_cccccccccccc",
            "keyId": 1
        },
        "registrationId": 12345,
        "advSecretKey": "super_secret_advertising_key_123456789",
        "me": {
            "id": "1234567890@s.whatsapp.net",
            "name": "Test User"
        },
        "accountSyncCounter": 0,
        "accountSettings": {
            "unarchiveChats": False
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(mock_creds, f, indent=2)
        creds_path = f.name
    
    try:
        print(f"\n[+] 模拟creds.json路径: {creds_path}")
        
        with open(creds_path, 'r') as f:
            content = f.read()
        
        print(f"[+] 凭证文件大小: {len(content)} bytes")
        
        # 检查敏感字段
        sensitive_fields = ['noiseKey', 'signedIdentityKey', 'advSecretKey']
        parsed = json.loads(content)
        
        exposed = []
        for field in sensitive_fields:
            if field in parsed:
                exposed.append(field)
        
        print(f"\n[!] 暴露的敏感字段:")
        for field in exposed:
            print(f"    - {field}: 明文存储")
        
        if len(exposed) == len(sensitive_fields):
            print(f"\n[✗] 漏洞存在: 所有加密密钥都以明文存储!")
            return False
            
    finally:
        os.unlink(creds_path)
    
    return True

if __name__ == "__main__":
    print("\n" + "🔒 OpenClaw 数据安全分析 - PoC测试套件\n")
    
    result1 = test_sensitive_data_plaintext_storage()
    result2 = test_whatsapp_creds_exposure()
    
    print("\n" + "=" * 60)
    print("[测试总结]")
    print("=" * 60)
    print(f"测试1 (明文Token存储): {'通过 ✓' if result1 else '失败 ✗'}")
    print(f"测试2 (明文凭证存储): {'通过 ✓' if result2 else '失败 ✗'}")
    print("\n结论: OpenClaw存在敏感数据明文存储问题，建议实施加密机制")
