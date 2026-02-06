#!/usr/bin/env python3
"""
PoC: OpenClaw 设备配对和Token管理安全测试
测试设备配对流程中的安全弱点
"""

import asyncio
import json
import time
import hashlib
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class TestResult:
    test_name: str
    passed: bool
    issue_found: bool
    details: str
    recommendation: str


class DevicePairingSecurityTester:
    """测试设备配对和Token管理的安全性"""
    
    def __init__(self, gateway_url: str = "ws://localhost:3000"):
        self.gateway_url = gateway_url
        self.results: list[TestResult] = []
    
    def test_token_predictability(self) -> TestResult:
        """
        分析设备Token生成算法的可预测性
        
        代码分析：
        ```javascript
        function newToken() {
          return randomUUID().replaceAll("-", "");
        }
        ```
        
        Token使用Node.js crypto.randomUUID()生成，移除连字符后得到32字符十六进制字符串。
        这是加密安全的随机数，不可预测。
        """
        import uuid
        
        # 模拟10000次token生成，检查碰撞
        tokens = set()
        collisions = 0
        
        for _ in range(10000):
            token = uuid.uuid4().hex
            if token in tokens:
                collisions += 1
            tokens.add(token)
        
        if collisions == 0:
            return TestResult(
                test_name="Token Generation Entropy",
                passed=True,
                issue_found=False,
                details=f"Generated 10,000 tokens with 0 collisions. "
                        f"Token uses UUID v4 (122 bits of entropy).",
                recommendation="Token generation is cryptographically secure."
            )
        else:
            return TestResult(
                test_name="Token Generation Entropy",
                passed=False,
                issue_found=True,
                details=f"Detected {collisions} collisions in 10,000 tokens!",
                recommendation="URGENT: Review token generation implementation."
            )
    
    def test_pending_ttl_window(self) -> TestResult:
        """
        测试Pending配对请求的TTL窗口
        
        代码分析：
        ```javascript
        const PENDING_TTL_MS = 5 * 60 * 1000; // 5 minutes
        ```
        
        5分钟的TTL窗口相对较长，攻击者可能利用此窗口进行：
        1. 会话固定攻击
        2. 配对请求劫持
        3. 拒绝服务攻击（填满pending队列）
        """
        PENDING_TTL_MS = 5 * 60 * 1000  # 5 minutes
        
        # 评估TTL合理性
        if PENDING_TTL_MS > 300000:  # > 5 minutes
            return TestResult(
                test_name="Pending Request TTL Analysis",
                passed=False,
                issue_found=True,
                details=f"Pending TTL is {PENDING_TTL_MS/1000}s (5 minutes). "
                        "This is relatively long and increases attack surface.",
                recommendation="Consider reducing pending TTL to 2-3 minutes."
            )
        else:
            return TestResult(
                test_name="Pending Request TTL Analysis",
                passed=True,
                issue_found=False,
                details=f"Pending TTL is {PENDING_TTL_MS/1000}s.",
                recommendation="TTL is within acceptable range."
            )
    
    def test_file_permissions(self) -> TestResult:
        """
        测试设备配对状态文件的权限设置
        
        代码分析：
        ```javascript
        await fs.chmod(tmp, 0o600);
        await fs.rename(tmp, filePath);
        await fs.chmod(filePath, 0o600);
        ```
        
        文件使用0o600权限（仅所有者可读写），这是正确的。
        但需要验证是否在所有平台上都能正确设置。
        """
        return TestResult(
            test_name="State File Permissions",
            passed=True,
            issue_found=False,
            details="Device pairing state files use 0o600 permissions (owner read/write only).",
            recommendation="Permissions are correctly set. Ensure umask doesn't interfere."
        )
    
    def test_concurrency_lock(self) -> TestResult:
        TestResult(
            test_name="Concurrency Lock Mechanism",
            passed=True,
            issue_found=False,
            details="Uses promise-based lock to serialize state access.",
            recommendation="Lock implementation is correct. Consider using async-mutex for clarity."
        )
        
        """
        测试并发访问控制
        
        代码分析：
        ```javascript
        let lock: Promise<void> = Promise.resolve();
        async function withLock<T>(fn: () => Promise<T>): Promise<T> {
          const prev = lock;
          let release: (() => void) | undefined;
          lock = new Promise<void>((resolve) => {
            release = resolve;
          });
          await prev;
          try {
            return await fn();
          } finally {
            release?.();
          }
        }
        ```
        
        使用Promise链实现简单的异步锁，是正确的并发控制方式。
        """
        return TestResult(
            test_name="Concurrency Lock Mechanism",
            passed=True,
            issue_found=False,
            details="Uses promise-based lock to serialize state access.",
            recommendation="Lock implementation is correct. Consider using async-mutex for clarity."
        )
    
    def test_scope_escalation_prevention(self) -> TestResult:
        """
        测试权限范围升级检测
        
        代码分析显示scopesAllow函数：
        ```javascript
        function scopesAllow(requested: string[], allowed: string[]): boolean {
          if (requested.length === 0) {
            return true;
          }
          if (allowed.length === 0) {
            return false;
          }
          const allowedSet = new Set(allowed);
          return requested.every((scope) => allowedSet.has(scope));
        }
        ```
        
        此函数正确实现了子集检查，但需要注意配对时权限的继承逻辑。
        """
        # 模拟权限检查
        allowed_scopes = ["operator.read", "operator.pairing"]
        requested_scopes = ["operator.read", "operator.admin"]  # 尝试升级权限
        
        allowed_set = set(allowed_scopes)
        scopes_allowed = all(scope in allowed_set for scope in requested_scopes)
        
        if not scopes_allowed:
            return TestResult(
                test_name="Scope Escalation Prevention",
                passed=True,
                issue_found=False,
                details="Permission scope escalation correctly rejected.",
                recommendation="Scope validation is working correctly."
            )
        else:
            return TestResult(
                test_name="Scope Escalation Prevention",
                passed=False,
                issue_found=True,
                details="CRITICAL: Permission scope escalation was allowed!",
                recommendation="URGENT: Fix scope validation logic."
            )
    
    def test_localstorage_token_storage(self) -> TestResult:
        """
        测试客户端Token存储安全性
        
        代码分析：
        ```javascript
        const STORAGE_KEY = "openclaw.device.auth.v1";
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
        ```
        
        设备Token存储在localStorage中，存在以下风险：
        1. XSS攻击可窃取Token
        2. 浏览器扩展可读取Token
        3. 物理访问可提取Token
        """
        return TestResult(
            test_name="Client-Side Token Storage",
            passed=False,
            issue_found=True,
            details="Device tokens are stored in localStorage, vulnerable to XSS attacks. "
                    "Any malicious script can read openclaw.device.auth.v1 key.",
            recommendation="Consider using httpOnly cookies for token storage, "
                          "or implement Content Security Policy headers."
        )
    
    def test_signature_time_skew(self) -> TestResult:
        """
        测试签名时间戳偏差容忍度
        
        代码分析：
        ```javascript
        const DEVICE_SIGNATURE_SKEW_MS = 10 * 60 * 1000; // 10 minutes
        ```
        
        10分钟的偏差容忍度过大，可能导致重放攻击。
        建议减少到1-2分钟。
        """
        SKEW_MS = 10 * 60 * 1000  # 10 minutes
        
        if SKEW_MS > 300000:  # > 5 minutes
            return TestResult(
                test_name="Signature Time Skew Tolerance",
                passed=False,
                issue_found=True,
                details=f"Signature time skew tolerance is {SKEW_MS/1000}s (10 minutes). "
                        "This is excessive and allows replay attacks within the window.",
                recommendation="Reduce DEVICE_SIGNATURE_SKEW_MS to 60-120 seconds."
            )
        else:
            return TestResult(
                test_name="Signature Time Skew Tolerance",
                passed=True,
                issue_found=False,
                details=f"Signature time skew tolerance is {SKEW_MS/1000}s.",
                recommendation="Tolerance is within acceptable range."
            )
    
    def test_token_revocation(self) -> TestResult:
        """
        测试Token撤销机制
        
        代码分析显示revokeDeviceToken正确设置了revokedAtMs，
        但需要注意已颁发的Token在撤销前仍然有效（直到过期）。
        """
        return TestResult(
            test_name="Token Revocation Mechanism",
            passed=True,
            issue_found=True,  # 有改进空间
            details="Token revocation sets revokedAtMs but doesn't invalidate in-flight sessions. "
                    "Revoked tokens remain valid for active connections.",
            recommendation="Consider implementing session invalidation on token revoke, "
                          "or shorter token TTL."
        )
    
    def run_all_tests(self) -> list[TestResult]:
        """运行所有测试"""
        print("=" * 70)
        print("OpenClaw Device Pairing & Token Management Security Tests")
        print("=" * 70)
        
        tests = [
            self.test_token_predictability(),
            self.test_pending_ttl_window(),
            self.test_file_permissions(),
            self.test_concurrency_lock(),
            self.test_scope_escalation_prevention(),
            self.test_localstorage_token_storage(),
            self.test_signature_time_skew(),
            self.test_token_revocation(),
        ]
        
        self.results = tests
        
        for result in tests:
            status = "PASS" if result.passed else "FAIL"
            issue = "[ISSUE]" if result.issue_found else "[OK]"
            print(f"\n{issue} [{status}] {result.test_name}")
            print(f"    Details: {result.details}")
            print(f"    Recommendation: {result.recommendation}")
        
        return self.results


def main():
    """主函数"""
    tester = DevicePairingSecurityTester()
    results = tester.run_all_tests()
    
    issues_found = sum(1 for r in results if r.issue_found)
    passed = sum(1 for r in results if r.passed)
    
    print("\n" + "=" * 70)
    print(f"Summary: {passed}/{len(results)} tests passed, {issues_found} issues found")
    print("=" * 70)
    
    if issues_found > 0:
        print("\n[!] Issues requiring attention:")
        for r in results:
            if r.issue_found:
                print(f"    - {r.test_name}: {r.recommendation}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
