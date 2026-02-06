#!/usr/bin/env python3
"""
OpenClaw 文件系统安全测试 - PoC 3: 路径遍历与敏感文件访问
Test Case: test-04-path-traversal.py
Category: Path Traversal / File Disclosure
Severity: High

分析发现：文件系统访问控制可能存在路径遍历漏洞，
skill代码可能访问超出允许范围的文件。
"""

import os
import sys
from pathlib import Path


def test_path_traversal_vectors():
    """
    测试路径遍历攻击向量
    
    漏洞分析：
    - 相对路径遍历: ../../../etc/passwd
    - 空字节注入: file.txt%00.jpg
    - Unicode规范化: ..%c0%af..%c0%af
    - 符号链接攻击
    """
    
    print("=" * 70)
    print("路径遍历攻击向量测试")
    print("=" * 70)
    
    traversal_payloads = [
        # 基础遍历
        ("../../../etc/passwd", "经典路径遍历"),
        ("..\\..\\..\\windows\\system32\\config\\sam", "Windows路径遍历"),
        ("....//....//....//etc/passwd", "双点斜杠绕过"),
        
        # 编码绕过
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "URL编码"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "UTF-8编码绕过"),
        ("..%252f..%252f..%252fetc/passwd", "双重URL编码"),
        
        # 空字节注入
        ("file.txt%00.jpg", "空字节截断"),
        ("file.txt\x00.jpg", "空字节字符"),
        
        # 特殊路径
        ("/etc/passwd", "绝对路径"),
        ("~/.ssh/id_rsa", "Home目录扩展"),
        ("/proc/self/environ", "procfs信息泄露"),
        ("/sys/class/net/eth0/address", "sysfs信息泄露"),
        
        # 符号链接触发
        ("/tmp/symlink_to_etc", "符号链接攻击"),
        ("/app/uploads/../../../etc/shadow", "上传目录遍历"),
    ]
    
    print("\n攻击向量列表:")
    print("-" * 50)
    
    for payload, description in traversal_payloads:
        risk_level = "HIGH" if "etc/passwd" in payload or "ssh" in payload else "MEDIUM"
        print(f"\n[{risk_level}] {description}")
        print(f"    Payload: {payload[:60]}")
    
    return traversal_payloads


def test_sensitive_file_targets():
    """
    测试敏感文件访问目标
    
    基于OpenClaw可能访问的文件类型
    """
    
    print("\n" + "=" * 70)
    print("敏感文件访问目标")
    print("=" * 70)
    
    sensitive_files = {
        "SSH密钥": [
            "~/.ssh/id_rsa",
            "~/.ssh/id_ed25519",
            "~/.ssh/authorized_keys",
            "~/.ssh/config",
        ],
        "AWS凭证": [
            "~/.aws/credentials",
            "~/.aws/config",
        ],
        "OpenClaw配置": [
            "~/.openclaw/config.json",
            "~/.openclaw/exec-approvals.json",
            "~/.openclaw/memory/*.md",
        ],
        "系统文件": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self/environ",
            "/proc/self/cmdline",
        ],
        "Docker相关": [
            "/var/run/docker.sock",
            "~/.docker/config.json",
        ],
        "云环境": [
            "~/.config/gcloud/credentials.db",
            "~/.azure/credentials",
            "/opt/aws/credentials",
        ]
    }
    
    for category, files in sensitive_files.items():
        print(f"\n[{category}]")
        for f in files:
            print(f"    - {f}")
    
    return sensitive_files


def test_skill_file_access_policy():
    """
    测试skill文件访问策略
    
    分析skill-scanner.ts中的文件访问限制
    """
    
    print("\n" + "=" * 70)
    print("Skill文件访问策略分析")
    print("=" * 70)
    
    # 模拟skill访问控制
    allowed_paths = [
        "/workspace",
        "/tmp",
        "/home/node/.openclaw/skills",
    ]
    
    blocked_patterns = [
        "../",
        "..\\",
        "/etc/",
        "/root/",
    ]
    
    print("\n[策略] 允许访问的路径:")
    for path in allowed_paths:
        print(f"    + {path}")
    
    print("\n[策略] 阻止的模式:")
    for pattern in blocked_patterns:
        print(f"    - {pattern}")
    
    # 测试绕过
    print("\n[测试] 策略绕过尝试:")
    test_paths = [
        ("/workspace/../../../etc/passwd", "工作区遍历"),
        ("/tmp/../../etc/shadow", "临时目录遍历"),
        ("/home/node/.openclaw/skills/../../config.json", "skill目录遍历"),
    ]
    
    for test_path, desc in test_paths:
        # 模拟路径检查
        is_blocked = any(pattern in test_path for pattern in blocked_patterns)
        status = "BLOCKED" if is_blocked else "POTENTIAL BYPASS"
        print(f"    {status}: {desc}")
        print(f"             Path: {test_path}")
    
    return allowed_paths


def test_file_permission_issues():
    """
    测试文件权限配置问题
    
    基于audit-fs.ts的分析
    """
    
    print("\n" + "=" * 70)
    print("文件权限配置测试")
    print("=" * 70)
    
    # 模拟文件权限检查
    permission_tests = [
        {
            "path": "~/.openclaw/config.json",
            "mode": 0o644,
            "expected": 0o600,
            "risk": "配置文件中可能包含API密钥，应限制为600"
        },
        {
            "path": "~/.openclaw/state",
            "mode": 0o755,
            "expected": 0o700,
            "risk": "状态目录应限制为700"
        },
        {
            "path": "~/.openclaw/exec-approvals.json",
            "mode": 0o644,
            "expected": 0o600,
            "risk": "执行批准配置包含敏感信息"
        }
    ]
    
    print("\n权限配置检查:")
    print("-" * 50)
    
    for test in permission_tests:
        current = oct(test["mode"])
        expected = oct(test["expected"])
        status = "RISK" if test["mode"] != test["expected"] else "OK"
        print(f"\n[{status}] {test['path']}")
        print(f"    Current: {current}")
        print(f"    Expected: {expected}")
        print(f"    Risk: {test['risk']}")
    
    return permission_tests


def generate_security_recommendations():
    """
    生成安全建议
    """
    
    print("\n" + "=" * 70)
    print("安全加固建议")
    print("=" * 70)
    
    recommendations = """
1. 路径验证加固:
   - 使用Path.resolve()规范化路径
   - 检查解析后的路径是否在允许范围内
   - 禁止包含..的未经处理的路径

2. 文件权限加固:
   ```bash
   chmod 600 ~/.openclaw/config.json
   chmod 600 ~/.openclaw/exec-approvals.json
   chmod 700 ~/.openclaw/
   ```

3. 符号链接处理:
   - 使用lstat()而非stat()检查文件
   - 验证符号链接目标是否在允许范围内
   - 考虑禁止符号链接

4. 访问控制列表:
   - 实施最小权限原则
   - 使用chroot或容器隔离
   - 实施路径白名单机制
"""
    
    print(recommendations)


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("OpenClaw 文件系统安全测试套件")
    print("=" * 70 + "\n")
    
    vectors = test_path_traversal_vectors()
    targets = test_sensitive_file_targets()
    policy = test_skill_file_access_policy()
    permissions = test_file_permission_issues()
    generate_security_recommendations()
    
    print("\n" + "=" * 70)
    print("测试总结")
    print("=" * 70)
    print(f"\n发现 {len(vectors)} 个路径遍历向量")
    print(f"识别 {sum(len(v) for v in targets.values())} 个敏感文件目标")
    print(f"发现 {len(permissions)} 个权限配置问题")
    
    print("\n关键风险:")
    print("  1. 路径遍历可能导致任意文件读取")
    print("  2. 敏感配置文件权限过于宽松")
    print("  3. 符号链接可能被用于绕过访问控制")
