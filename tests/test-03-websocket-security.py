#!/usr/bin/env python3
"""
PoC Test: WebSocket Communication Security Testing
测试目标: OpenClaw WebSocket通信模块 (ws.ts)
安全风险: 消息完整性、编码攻击、重放攻击
"""

import asyncio
import websockets
import json
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class WSMessage:
    """WebSocket消息结构"""
    type: str
    payload: Any
    timestamp: float
    sequence: int


class WebSocketSecurityTest:
    """WebSocket安全测试类"""
    
    def __init__(self, ws_url: str):
        self.ws_url = ws_url
        self.test_results: List[Dict[str, Any]] = []
        self.sequence_counter = 0
    
    def _create_message(self, msg_type: str, payload: Any) -> str:
        """创建测试消息"""
        self.sequence_counter += 1
        msg = {
            "type": msg_type,
            "payload": payload,
            "timestamp": time.time(),
            "sequence": self.sequence_counter
        }
        return json.dumps(msg)
    
    async def test_01_encoding_attack(self):
        """测试1: 编码攻击测试"""
        print("[*] 测试1: WebSocket编码攻击...")
        
        # 各种编码测试载荷
        encoding_payloads = [
            # UTF-8边界测试
            "Hello\x00World",  # null字节
            "Test\xff\xfeData",  # 无效UTF-8序列
            "\xc0\x80",  # overlong encoding
            # Unicode规范化攻击
            "caf\u0065\u0301",  # 组合字符
            "\u0041\u030A",  # 带圈的A
            # 全角字符绕过
            "＜＜＜EXTERNAL_UNTRUSTED_CONTENT＞＞＞",
            # 混合编码
            b"\x80\x81\x82".decode('latin1', errors='ignore'),
        ]
        
        results = []
        for payload in encoding_payloads:
            try:
                async with websockets.connect(self.ws_url, timeout=5) as ws:
                    msg = self._create_message("test", payload)
                    await ws.send(msg)
                    response = await asyncio.wait_for(ws.recv(), timeout=5)
                    results.append({
                        "payload": repr(payload)[:50],
                        "response_received": True,
                        "response_length": len(response)
                    })
            except Exception as e:
                results.append({
                    "payload": repr(payload)[:50],
                    "error": str(e)[:100]
                })
        
        result = {
            "test": "encoding_attack",
            "results": results,
            "vulnerable": len([r for r in results if r.get("response_received")]) > 0
        }
        self.test_results.append(result)
        return result
    
    async def test_02_message_flooding(self):
        """测试2: 消息洪泛攻击"""
        print("[*] 测试2: WebSocket消息洪泛测试...")
        
        message_count = 100
        success_count = 0
        errors = []
        
        try:
            async with websockets.connect(self.ws_url) as ws:
                start_time = time.time()
                for i in range(message_count):
                    try:
                        msg = self._create_message("flood", {"index": i, "data": "A" * 1000})
                        await ws.send(msg)
                        success_count += 1
                    except Exception as e:
                        errors.append(str(e))
                end_time = time.time()
                
                result = {
                    "test": "message_flooding",
                    "messages_sent": message_count,
                    "success_count": success_count,
                    "duration": end_time - start_time,
                    "rate": success_count / (end_time - start_time) if end_time > start_time else 0,
                    "vulnerable": success_count > message_count * 0.9  # 90%成功率视为脆弱
                }
        except Exception as e:
            result = {
                "test": "message_flooding",
                "error": str(e),
                "vulnerable": False
            }
        
        self.test_results.append(result)
        return result
    
    async def test_03_replay_attack(self):
        """测试3: 重放攻击测试"""
        print("[*] 测试3: WebSocket重放攻击...")
        
        # 捕获并重放消息
        captured_messages = []
        
        try:
            # 第一阶段：捕获消息
            async with websockets.connect(self.ws_url) as ws:
                for i in range(5):
                    msg = self._create_message("command", {"action": "test", "id": i})
                    await ws.send(msg)
                    captured_messages.append(msg)
                    await asyncio.sleep(0.1)
            
            # 第二阶段：重放消息
            replay_success = 0
            async with websockets.connect(self.ws_url) as ws:
                for msg in captured_messages:
                    try:
                        await ws.send(msg)
                        replay_success += 1
                    except:
                        pass
            
            result = {
                "test": "replay_attack",
                "captured_messages": len(captured_messages),
                "replay_success": replay_success,
                "vulnerable": replay_success > 0,
                "note": "WebSocket缺少消息序号/时间戳验证时易受重放攻击"
            }
        except Exception as e:
            result = {
                "test": "replay_attack",
                "error": str(e),
                "vulnerable": False
            }
        
        self.test_results.append(result)
        return result
    
    async def test_04_frame_manipulation(self):
        """测试4: WebSocket帧操作测试"""
        print("[*] 测试4: WebSocket帧操作测试...")
        
        frame_tests = [
            {"type": "binary", "data": b"\x00\x01\x02\x03" * 100},
            {"type": "text_large", "data": "X" * 100000},  # 大消息
            {"type": "fragmented", "data": "part1" + "part2" + "part3"},
            {"type": "control", "data": json.dumps({"op": 9})},  # ping帧模拟
        ]
        
        results = []
        for test in frame_tests:
            try:
                async with websockets.connect(self.ws_url) as ws:
                    if test["type"] == "binary":
                        await ws.send(test["data"])
                    else:
                        await ws.send(test["data"])
                    
                    response = await asyncio.wait_for(ws.recv(), timeout=3)
                    results.append({
                        "type": test["type"],
                        "success": True,
                        "response_length": len(response) if isinstance(response, str) else len(str(response))
                    })
            except Exception as e:
                results.append({
                    "type": test["type"],
                    "success": False,
                    "error": str(e)[:100]
                })
        
        result = {
            "test": "frame_manipulation",
            "results": results,
            "vulnerable": any(r.get("success") for r in results if r["type"] in ["binary", "fragmented"])
        }
        self.test_results.append(result)
        return result
    
    async def test_05_protocol_upgrade_attack(self):
        """测试5: 协议升级攻击测试"""
        print("[*] 测试5: 协议升级攻击测试...")
        
        # 尝试使用不同的子协议
        subprotocols = [
            ["chat", "superchat"],
            [""],
            ["x" * 100],  # 超长协议名
            ["<script>alert(1)</script>"],  # XSS尝试
        ]
        
        results = []
        for proto in subprotocols:
            try:
                async with websockets.connect(
                    self.ws_url,
                    subprotocols=proto if proto != [""] else None
                ) as ws:
                    results.append({
                        "protocol": str(proto)[:50],
                        "accepted": True,
                        "selected": ws.subprotocol
                    })
            except Exception as e:
                results.append({
                    "protocol": str(proto)[:50],
                    "accepted": False,
                    "error": str(e)[:50]
                })
        
        result = {
            "test": "protocol_upgrade",
            "results": results,
            "vulnerable": any(r.get("accepted") and "script" in str(r.get("protocol", "")) for r in results)
        }
        self.test_results.append(result)
        return result
    
    def generate_report(self) -> str:
        """生成测试报告"""
        report_lines = [
            "=" * 60,
            "WebSocket Communication Security Test Report",
            "=" * 60,
            "",
            f"Target URL: {self.ws_url}",
            f"Tests Run: {len(self.test_results)}",
            ""
        ]
        
        for result in self.test_results:
            status = "⚠️ VULNERABLE" if result.get("vulnerable") else "✅ PASSED"
            report_lines.append(f"{status}: {result.get('test', 'unknown')}")
            
            if "results" in result:
                report_lines.append(f"  Details:")
                for detail in result["results"]:
                    report_lines.append(f"    - {detail}")
            if "error" in result:
                report_lines.append(f"  Error: {result['error']}")
        
        report_lines.extend([
            "",
            "=" * 60,
            "Security Recommendations:",
            "1. 实现消息序列号验证防止重放攻击",
            "2. 添加速率限制防止消息洪泛",
            "3. 严格验证消息编码和字符集",
            "4. 使用WSS (WebSocket Secure) 加密通信",
            "5. 实现消息大小限制",
            "6. 添加连接认证机制"
        ])
        
        return "\n".join(report_lines)
    
    async def run_all_tests(self):
        """运行所有测试"""
        print("\n🔒 OpenClaw WebSocket Security PoC Test")
        print("=" * 60)
        
        await self.test_01_encoding_attack()
        await self.test_02_message_flooding()
        await self.test_03_replay_attack()
        await self.test_04_frame_manipulation()
        await self.test_05_protocol_upgrade_attack()
        
        report = self.generate_report()
        print("\n" + report)
        
        # 保存报告
        with open("/Users/xdrshjr/.openclaw/workspace/openclaw-security-analysis/tests/test-03-websocket-report.txt", "w") as f:
            f.write(report)
        
        print("\n💾 报告已保存到 tests/test-03-websocket-report.txt")


def main():
    """主函数"""
    ws_url = "ws://localhost:8080/ws"  # 示例URL
    
    tester = WebSocketSecurityTest(ws_url)
    
    try:
        asyncio.run(tester.run_all_tests())
    except KeyboardInterrupt:
        print("\n[!] 测试被用户中断")
    except Exception as e:
        print(f"\n[!] 测试出错: {e}")


if __name__ == "__main__":
    main()
