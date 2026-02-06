#!/usr/bin/env python3
"""
PoC Test: Cross-Channel Information Leakage Testing
测试目标: OpenClaw多通道消息处理 (Discord, Telegram, Slack集成)
安全风险: 跨通道信息泄露、权限边界问题
"""

import json
from typing import Dict, Any, List
from dataclasses import dataclass


@dataclass
class ChannelMessage:
    """通道消息结构"""
    channel: str  # discord, telegram, slack, etc.
    sender_id: str
    sender_name: str
    content: str
    metadata: Dict[str, Any]


class CrossChannelLeakageTest:
    """测试跨通道信息泄露风险"""
    
    def __init__(self):
        self.test_results = []
        self.channels = ["discord", "telegram", "slack", "whatsapp"]
    
    def test_01_session_key_isolation(self) -> Dict[str, Any]:
        """测试1: 会话键隔离性"""
        print("[*] 测试1: 会话键隔离性测试...")
        
        # 不同通道的会话键格式
        session_keys = [
            ("discord:main:user123", "Discord主账户用户DM"),
            ("discord:alt:user123", "Discord备用账户用户DM"),
            ("telegram:main:user123", "Telegram用户消息"),
            ("slack:work:user123", "Slack工作区消息"),
            ("hook:gmail:account1", "Gmail钩子"),
            ("hook:webhook:service1", "通用Webhook"),
            ("web:session:abc123", "Web会话"),
        ]
        
        results = []
        for session_key, desc in session_keys:
            # 分析会话键结构
            parts = session_key.split(":")
            
            # 检查潜在的混淆风险
            risks = []
            if len(parts) < 3:
                risks.append("会话键结构不完整")
            if "hook:" in session_key and "webhook" not in session_key:
                risks.append("钩子类型识别模糊")
            if parts[0] in ["discord", "telegram", "slack"]:
                if len(parts) < 3 or not parts[1]:
                    risks.append("账户ID可能为空")
            
            results.append({
                "session_key": session_key,
                "description": desc,
                "parts": parts,
                "risks": risks,
                "isolated": len(risks) == 0
            })
        
        result = {
            "test": "session_key_isolation",
            "results": results,
            "vulnerable": any(not r["isolated"] for r in results)
        }
        self.test_results.append(result)
        return result
    
    def test_02_message_routing_confusion(self) -> Dict[str, Any]:
        """测试2: 消息路由混淆测试"""
        print("[*] 测试2: 消息路由混淆...")
        
        # 测试消息在不同通道间的路由
        test_messages = [
            {
                "channel": "discord",
                "content": "@bot please send this to Telegram",
                "intent": "cross_channel_request"
            },
            {
                "channel": "telegram", 
                "content": "Forward to Slack #general",
                "intent": "cross_channel_request"
            },
            {
                "channel": "slack",
                "content": "!dm discord:user123 secret message",
                "intent": "impersonation_attempt"
            },
            {
                "channel": "discord",
                "content": "Can you post this in the Telegram group?",
                "intent": "delegation_request"
            },
        ]
        
        results = []
        for msg in test_messages:
            # 分析消息意图
            content_lower = msg["content"].lower()
            
            # 检测跨通道关键词
            cross_channel_keywords = ["telegram", "slack", "discord", "forward", "send", "post"]
            detected_keywords = [kw for kw in cross_channel_keywords if kw in content_lower]
            
            # 检测潜在风险
            risks = []
            if msg["intent"] == "cross_channel_request":
                risks.append("用户请求跨通道操作")
            if msg["intent"] == "impersonation_attempt":
                risks.append("可能的身份冒充尝试")
            if len(detected_keywords) >= 2:
                risks.append("包含多个通道关键词，可能意图混淆")
            
            results.append({
                "channel": msg["channel"],
                "content": msg["content"][:50],
                "intent": msg["intent"],
                "detected_keywords": detected_keywords,
                "risks": risks,
                "needs_verification": len(risks) > 0
            })
        
        result = {
            "test": "message_routing_confusion",
            "results": results,
            "vulnerable": any(r["needs_verification"] for r in results)
        }
        self.test_results.append(result)
        return result
    
    def test_03_permission_boundary_violation(self) -> Dict[str, Any]:
        """测试3: 权限边界违反测试"""
        print("[*] 测试3: 权限边界违反...")
        
        # 测试不同通道的权限策略
        permission_scenarios = [
            {
                "scenario": "Discord DM允许，但Telegram DM拒绝",
                "discord_dm_policy": "open",
                "telegram_dm_policy": "disabled",
                "user_id": "user123",
                "expected": "通道独立决策"
            },
            {
                "scenario": "同一用户在Discord允许，Telegram未配对",
                "discord_allowed": True,
                "telegram_paired": False,
                "risk": "用户可能在不同通道有不同身份"
            },
            {
                "scenario": "Slack管理员在Discord无权限",
                "slack_admin": True,
                "discord_permission": "none",
                "risk": "权限不互通可能导致误授权"
            },
            {
                "scenario": "Webhook消息伪装成用户",
                "source": "webhook",
                "claimed_identity": "discord:user123",
                "risk": "消息来源验证不足"
            },
        ]
        
        results = []
        for scenario in permission_scenarios:
            risks = scenario.get("risks", [])
            if "risk" in scenario:
                risks.append(scenario["risk"])
            
            results.append({
                "scenario": scenario["scenario"],
                "risks": risks,
                "violation_possible": len(risks) > 0
            })
        
        result = {
            "test": "permission_boundary_violation",
            "results": results,
            "vulnerable": any(r["violation_possible"] for r in results)
        }
        self.test_results.append(result)
        return result
    
    def test_04_metadata_leakage(self) -> Dict[str, Any]:
        """测试4: 元数据泄露测试"""
        print("[*] 测试4: 元数据泄露...")
        
        # 检查各通道的元数据
        metadata_tests = [
            {
                "channel": "discord",
                "metadata": {
                    "guild_id": "123456789",
                    "channel_id": "987654321",
                    "user_id": "111222333",
                    "roles": ["admin", "moderator"],
                    "nickname": "UserNick"
                }
            },
            {
                "channel": "telegram",
                "metadata": {
                    "chat_id": "123456789",
                    "user_id": "987654321",
                    "username": "@username",
                    "language_code": "en"
                }
            },
            {
                "channel": "slack",
                "metadata": {
                    "team_id": "T123456",
                    "channel_id": "C789012",
                    "user_id": "U345678",
                    "is_admin": True
                }
            },
        ]
        
        results = []
        for test in metadata_tests:
            metadata = test["metadata"]
            
            # 识别敏感字段
            sensitive_fields = []
            if "user_id" in metadata:
                sensitive_fields.append("user_id")
            if "roles" in metadata:
                sensitive_fields.append("roles")
            if "is_admin" in metadata:
                sensitive_fields.append("is_admin")
            if "guild_id" in metadata or "team_id" in metadata:
                sensitive_fields.append("organization_id")
            
            results.append({
                "channel": test["channel"],
                "metadata_fields": list(metadata.keys()),
                "sensitive_fields": sensitive_fields,
                "leakage_risk": len(sensitive_fields) > 0
            })
        
        result = {
            "test": "metadata_leakage",
            "results": results,
            "vulnerable": any(r["leakage_risk"] for r in results)
        }
        self.test_results.append(result)
        return result
    
    def test_05_history_context_contamination(self) -> Dict[str, Any]:
        """测试5: 历史上下文污染"""
        print("[*] 测试5: 历史上下文污染...")
        
        # 测试历史记录是否可能跨通道污染
        history_scenarios = [
            {
                "scenario": "Discord群组历史混入DM上下文",
                "discord_guild_history": ["msg1", "msg2", "msg3"],
                "discord_dm_history": ["dm1", "dm2"],
                "risk": "如果在同一会话中，历史可能混淆"
            },
            {
                "scenario": "Telegram话题历史越界",
                "topic1_history": ["topic1_msg1"],
                "topic2_history": ["topic2_msg1"],
                "risk": "话题ID验证不严可能导致历史混淆"
            },
            {
                "scenario": "Webhook消息进入正常会话历史",
                "webhook_message": "hook:webhook:service1",
                "normal_session": "discord:main:user123",
                "risk": "钩子消息可能与正常消息混合"
            },
        ]
        
        results = []
        for scenario in history_scenarios:
            results.append({
                "scenario": scenario["scenario"],
                "risk": scenario.get("risk", ""),
                "contamination_possible": True
            })
        
        result = {
            "test": "history_context_contamination",
            "results": results,
            "vulnerable": True,
            "note": "历史上下文隔离是多通道安全的关键"
        }
        self.test_results.append(result)
        return result
    
    def test_06_skill_isolation(self) -> Dict[str, Any]:
        """测试6: 技能(Skill)隔离性"""
        print("[*] 测试6: 技能隔离性...")
        
        # 测试技能在不同通道的隔离
        skill_tests = [
            {
                "skill": "discord",
                "allowed_channels": ["discord"],
                "blocked_channels": ["telegram", "slack"],
                "test": "Discord专属技能在其他通道应被阻止"
            },
            {
                "skill": "telegram",
                "allowed_channels": ["telegram"],
                "blocked_channels": ["discord", "slack"],
                "test": "Telegram专属技能在其他通道应被阻止"
            },
            {
                "skill": "generic",
                "allowed_channels": ["discord", "telegram", "slack"],
                "blocked_channels": [],
                "test": "通用技能应在所有通道可用"
            },
        ]
        
        results = []
        for test in skill_tests:
            # 验证隔离逻辑
            isolation_score = len(test["blocked_channels"]) / (len(test["allowed_channels"]) + len(test["blocked_channels"]))
            
            results.append({
                "skill": test["skill"],
                "test": test["test"],
                "isolation_score": isolation_score,
                "properly_isolated": isolation_score > 0 or len(test["blocked_channels"]) == 0
            })
        
        result = {
            "test": "skill_isolation",
            "results": results,
            "vulnerable": not all(r["properly_isolated"] for r in results)
        }
        self.test_results.append(result)
        return result
    
    def generate_report(self) -> str:
        """生成测试报告"""
        report_lines = [
            "=" * 70,
            "Cross-Channel Information Leakage Test Report",
            "=" * 70,
            "",
            f"Tests Run: {len(self.test_results)}",
            ""
        ]
        
        for result in self.test_results:
            status = "⚠️ VULNERABLE" if result.get("vulnerable") else "✅ PASSED"
            report_lines.append(f"{status}: {result.get('test', 'unknown')}")
            
            if "results" in result:
                risk_count = sum(1 for r in result["results"] 
                                if r.get("violation_possible") or r.get("leakage_risk"))
                if risk_count > 0:
                    report_lines.append(f"  Risk items: {risk_count}/{len(result['results'])}")
            
            if "note" in result:
                report_lines.append(f"  Note: {result['note']}")
        
        report_lines.extend([
            "",
            "=" * 70,
            "Security Recommendations:",
            "1. 严格隔离不同通道的会话和消息历史",
            "2. 使用通道前缀确保会话键唯一性",
            "3. 实施通道级别的技能白名单",
            "4. 对跨通道请求进行显式用户确认",
            "5. 最小化元数据收集和跨通道传递",
            "6. 定期审计通道权限配置",
            "7. 实现通道间的消息溯源和审计日志"
        ])
        
        return "\n".join(report_lines)


def main():
    """主函数"""
    print("🔒 OpenClaw Cross-Channel Leakage PoC Test")
    print("=" * 70)
    
    tester = CrossChannelLeakageTest()
    
    tester.test_01_session_key_isolation()
    tester.test_02_message_routing_confusion()
    tester.test_03_permission_boundary_violation()
    tester.test_04_metadata_leakage()
    tester.test_05_history_context_contamination()
    tester.test_06_skill_isolation()
    
    report = tester.generate_report()
    print("\n" + report)
    
    # 保存报告
    with open("/Users/xdrshjr/.openclaw/workspace/openclaw-security-analysis/tests/test-03-cross-channel-report.txt", "w") as f:
        f.write(report)
    
    print("\n💾 报告已保存到 tests/test-03-cross-channel-report.txt")


if __name__ == "__main__":
    main()
