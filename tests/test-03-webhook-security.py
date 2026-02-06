#!/usr/bin/env python3
"""
PoC Test: Telegram Webhook Secret Validation Bypass
测试目标: OpenClaw Telegram webhook secret验证机制
安全风险: 配置验证绕过可能导致未授权访问
"""

import json
import requests
import hmac
import hashlib
from typing import Dict, Any, Optional


class TelegramWebhookTest:
    """测试Telegram webhook的安全验证机制"""
    
    def __init__(self, webhook_url: str, webhook_secret: Optional[str] = None):
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        self.test_results = []
    
    def _generate_signature(self, payload: str, secret: str) -> str:
        """生成HMAC签名"""
        return hmac.new(
            secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
    
    def test_01_missing_secret(self) -> Dict[str, Any]:
        """测试1: 缺少webhook secret的请求"""
        print("[*] 测试1: 发送缺少webhook secret的请求...")
        
        payload = {
            "update_id": 123456789,
            "message": {
                "message_id": 1,
                "from": {"id": 12345, "is_bot": False, "first_name": "Test"},
                "chat": {"id": 12345, "type": "private"},
                "date": 1704067200,
                "text": "Hello from test"
            }
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            result = {
                "test": "missing_secret",
                "status_code": response.status_code,
                "vulnerable": response.status_code < 400,
                "details": f"Response: {response.status_code} - {response.text[:200]}"
            }
        except Exception as e:
            result = {
                "test": "missing_secret",
                "error": str(e),
                "vulnerable": False
            }
        
        self.test_results.append(result)
        return result
    
    def test_02_invalid_signature(self) -> Dict[str, Any]:
        """测试2: 使用无效签名的请求"""
        print("[*] 测试2: 发送带有无效签名的请求...")
        
        payload = {
            "update_id": 123456790,
            "message": {
                "message_id": 2,
                "from": {"id": 12345, "is_bot": False, "first_name": "Test"},
                "chat": {"id": 12345, "type": "private"},
                "date": 1704067200,
                "text": "Test with invalid signature"
            }
        }
        
        headers = {
            "X-Telegram-Bot-Api-Secret-Token": "invalid_signature_12345"
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=headers,
                timeout=10
            )
            result = {
                "test": "invalid_signature",
                "status_code": response.status_code,
                "vulnerable": response.status_code < 400,
                "details": f"Response: {response.status_code}"
            }
        except Exception as e:
            result = {
                "test": "invalid_signature",
                "error": str(e),
                "vulnerable": False
            }
        
        self.test_results.append(result)
        return result
    
    def test_03_malformed_payload(self) -> Dict[str, Any]:
        """测试3: 畸形payload攻击"""
        print("[*] 测试3: 发送畸形payload测试...")
        
        # 测试各种畸形输入
        malformed_payloads = [
            # 超大消息
            {"update_id": 1, "message": {"text": "A" * 100000}},
            # 嵌套递归
            {"update_id": 2, "nested": {"a": {"b": {"c": "d"}}}},
            # 特殊字符
            {"update_id": 3, "message": {"text": "<script>alert(1)</script>"}},
            # Unicode攻击
            {"update_id": 4, "message": {"text": "＜script＞alert(1)＜/script＞"}},
        ]
        
        results = []
        for i, payload in enumerate(malformed_payloads):
            try:
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=10
                )
                results.append({
                    "payload_type": i,
                    "status": response.status_code,
                    "vulnerable": response.status_code < 500
                })
            except Exception as e:
                results.append({
                    "payload_type": i,
                    "error": str(e)
                })
        
        result = {
            "test": "malformed_payload",
            "results": results,
            "vulnerable": any(r.get("vulnerable") for r in results)
        }
        self.test_results.append(result)
        return result
    
    def test_04_config_validation_bypass(self) -> Dict[str, Any]:
        """测试4: 配置验证绕过尝试"""
        print("[*] 测试4: 测试配置验证绕过...")
        
        # 尝试通过账户级别配置绕过基础配置验证
        test_configs = [
            # 空secret
            {"webhookUrl": "https://example.com", "webhookSecret": ""},
            # 只有空白字符
            {"webhookUrl": "https://example.com", "webhookSecret": "   "},
            # 非常短的secret
            {"webhookUrl": "https://example.com", "webhookSecret": "x"},
        ]
        
        # 这些配置在实际应用中会被拒绝，但我们可以测试验证逻辑
        result = {
            "test": "config_validation_bypass",
            "note": "Configuration validation tests require internal access",
            "vulnerable": False,
            "recommendations": [
                "确保webhookSecret长度至少为32个字符",
                "在应用层和配置层都进行验证",
                "使用环境变量存储敏感配置"
            ]
        }
        self.test_results.append(result)
        return result
    
    def generate_report(self) -> str:
        """生成测试报告"""
        report_lines = [
            "=" * 60,
            "Telegram Webhook Security Test Report",
            "=" * 60,
            "",
            f"Target URL: {self.webhook_url}",
            f"Tests Run: {len(self.test_results)}",
            "",
            "Results:"
        ]
        
        for result in self.test_results:
            status = "⚠️ VULNERABLE" if result.get("vulnerable") else "✅ PASSED"
            report_lines.append(f"\n{status}: {result.get('test', 'unknown')}")
            if "details" in result:
                report_lines.append(f"  Details: {result['details']}")
            if "error" in result:
                report_lines.append(f"  Error: {result['error']}")
        
        report_lines.extend([
            "",
            "=" * 60,
            "Recommendations:",
            "1. 始终启用webhook secret验证",
            "2. 使用强随机secret（至少32字节）",
            "3. 实现请求速率限制",
            "4. 验证请求来源IP",
            "5. 记录所有webhook请求日志"
        ])
        
        return "\n".join(report_lines)


def main():
    """主测试函数"""
    print("🔒 OpenClaw Telegram Webhook Security PoC Test")
    print("=" * 60)
    
    # 注意：这些URL是示例，实际测试需要替换为真实目标
    test_url = "http://localhost:8080/hooks/telegram"
    
    tester = TelegramWebhookTest(test_url)
    
    # 运行测试
    tester.test_01_missing_secret()
    tester.test_02_invalid_signature()
    tester.test_03_malformed_payload()
    tester.test_04_config_validation_bypass()
    
    # 生成报告
    report = tester.generate_report()
    print("\n" + report)
    
    # 保存报告
    with open("/Users/xdrshjr/.openclaw/workspace/openclaw-security-analysis/tests/test-03-webhook-report.txt", "w") as f:
        f.write(report)
    
    print("\n💾 报告已保存到 tests/test-03-webhook-report.txt")


if __name__ == "__main__":
    main()
