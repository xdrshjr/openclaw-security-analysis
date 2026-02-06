#!/usr/bin/env python3
"""
OpenClaw 沙箱安全测试 - PoC 2: Docker沙箱逃逸与资源限制绕过
Test Case: test-04-sandbox-escape.py
Category: Sandbox Escape / Resource Exhaustion
Severity: Critical

分析发现：Dockerfile.sandbox配置过于宽松，缺乏安全加固措施。
"""

import json
import os
import sys
from pathlib import Path


def analyze_dockerfile_security():
    """
    分析Docker沙箱配置安全问题
    
    基于Dockerfile.sandbox的安全分析
    """
    
    dockerfile_content = """
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \\
  && apt-get install -y --no-install-recommends \\
    bash \\
    ca-certificates \\
    curl \\
    git \\
    jq \\
    python3 \\
    ripgrep \\
  && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
"""
    
    print("=" * 70)
    print("Docker沙箱安全配置分析")
    print("=" * 70)
    
    findings = []
    
    # 检查1: 容器以root运行
    print("\n[检查1] 容器用户权限")
    print("-" * 40)
    if "USER" not in dockerfile_content:
        findings.append({
            "severity": "HIGH",
            "issue": "容器默认以root用户运行",
            "detail": "Dockerfile中未指定USER指令，容器将以root运行",
            "impact": "代码执行获得root权限，增加逃逸风险"
        })
        print("[!] 风险: 容器以root用户运行")
        print("    建议: 添加 'USER 1000:1000' 限制权限")
    
    # 检查2: 安装工具过多
    print("\n[检查2] 攻击面分析")
    print("-" * 40)
    installed_tools = ["bash", "curl", "git", "python3"]
    print(f"[!] 安装工具: {', '.join(installed_tools)}")
    print("    风险: curl和git可用于下载和执行恶意代码")
    findings.append({
        "severity": "MEDIUM",
        "issue": "攻击面过大",
        "detail": f"安装了{len(installed_tools)}个工具，包括curl/git等高风险工具",
        "impact": "攻击者可利用这些工具下载和执行恶意载荷"
    })
    
    # 检查3: 缺少安全选项
    print("\n[检查3] 安全选项")
    print("-" * 40)
    missing_options = [
        ("--cap-drop=ALL", "未丢弃所有capabilities"),
        ("--security-opt=no-new-privileges", "未禁止提权"),
        ("--read-only", "未设置只读根文件系统"),
    ]
    for opt, desc in missing_options:
        print(f"[!] 缺少: {opt}")
        print(f"    问题: {desc}")
    
    return findings


def test_resource_limits():
    """
    测试资源限制配置
    
    漏洞分析：
    - 缺少CPU/内存限制
    - 缺少pids限制
    - 可能导致资源耗尽攻击
    """
    
    print("\n" + "=" * 70)
    print("资源限制测试")
    print("=" * 70)
    
    # 模拟资源限制攻击
    attacks = [
        {
            "name": "Fork Bomb",
            "command": ":(){ :|:& };:",
            "description": "经典的bash fork炸弹，耗尽进程表",
            "mitigation": "--pids-limit=100"
        },
        {
            "name": "Memory Exhaustion",
            "command": "python3 -c \"a=[]; [a.append('x'*10000000) for _ in range(1000)]\"",
            "description": "分配大量内存",
            "mitigation": "--memory=512m --memory-swap=512m"
        },
        {
            "name": "CPU Exhaustion",
            "command": "python3 -c \"while True: pass\"",
            "description": "无限循环占用CPU",
            "mitigation": "--cpus=0.5"
        },
        {
            "name": "Disk Fill",
            "command": "dd if=/dev/zero of=/tmp/fill bs=1M count=100000",
            "description": "填充磁盘空间",
            "mitigation": "--storage-opt size=1G"
        }
    ]
    
    print("\n潜在资源耗尽攻击向量:")
    print("-" * 40)
    
    for attack in attacks:
        print(f"\n[!] {attack['name']}")
        print(f"    命令: {attack['command'][:50]}...")
        print(f"    描述: {attack['description']}")
        print(f"    缓解: {attack['mitigation']}")
    
    return attacks


def test_volume_mount_risks():
    """
    测试卷挂载风险
    
    漏洞分析：
    - 挂载主机目录到容器
    - 可能导致主机文件系统暴露
    """
    
    print("\n" + "=" * 70)
    print("卷挂载安全风险分析")
    print("=" * 70)
    
    # 基于docker-compose.yml分析
    volume_mounts = [
        ("${OPENCLAW_CONFIG_DIR}", "/home/node/.openclaw"),
        ("${OPENCLAW_WORKSPACE_DIR}", "/home/node/.openclaw/workspace"),
    ]
    
    risks = []
    
    print("\n挂载的卷:")
    print("-" * 40)
    for host, container in volume_mounts:
        print(f"\n  {host} -> {container}")
        
        # 分析风险
        if ".openclaw" in container:
            risks.append({
                "mount": host,
                "risk": "配置文件可能包含敏感信息",
                "attack": "容器可读取主机API密钥和配置"
            })
            print("    [!] 风险: 配置文件暴露")
        
        if "workspace" in container:
            risks.append({
                "mount": host,
                "risk": "工作目录共享",
                "attack": "容器可修改主机工作区文件"
            })
            print("    [!] 风险: 工作目录可被容器修改")
    
    # 检查危险的挂载选项
    print("\n\n[警告] 缺少安全挂载选项:")
    print("-" * 40)
    print("  - 未使用 readonly 选项")
    print("  - 未限制设备访问")
    print("  - 未隔离命名空间")
    
    return risks


def generate_secure_dockerfile():
    """
    生成加固后的Dockerfile建议
    """
    
    print("\n" + "=" * 70)
    print("安全加固建议")
    print("=" * 70)
    
    secure_dockerfile = '''
# 加固版 Dockerfile.sandbox
FROM debian:bookworm-slim

# 创建非root用户
RUN groupadd -r openclaw -g 1000 && \\
    useradd -r -u 1000 -g openclaw -s /bin/bash openclaw

# 最小化安装
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
        ca-certificates \\
        jq && \\
    rm -rf /var/lib/apt/lists/*

# 设置工作目录权限
WORKDIR /workspace
RUN chown -R openclaw:openclaw /workspace

# 切换到非root用户
USER openclaw

CMD ["sleep", "infinity"]
'''
    
    print("\n[建议1] 加固Dockerfile:")
    print(secure_dockerfile)
    
    secure_run = '''
# 安全运行选项
docker run -d \\
  --name openclaw-sandbox \\
  --cap-drop=ALL \\
  --security-opt=no-new-privileges \\
  --read-only \\
  --tmpfs /tmp:noexec,nosuid,size=100m \\
  --memory=512m \\
  --memory-swap=512m \\
  --cpus=0.5 \\
  --pids-limit=100 \\
  --network=none \\
  -v /path/to/workspace:/workspace:ro \\
  openclaw:sandbox-secure
'''
    
    print("\n[建议2] 安全运行参数:")
    print(secure_run)


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("OpenClaw 沙箱安全测试套件")
    print("=" * 70)
    
    findings = analyze_dockerfile_security()
    attacks = test_resource_limits()
    risks = test_volume_mount_risks()
    generate_secure_dockerfile()
    
    print("\n" + "=" * 70)
    print("测试总结")
    print("=" * 70)
    print(f"\n发现 {len(findings)} 个配置问题")
    print(f"识别 {len(attacks)} 个资源攻击向量")
    print(f"发现 {len(risks)} 个挂载风险")
    
    print("\n关键建议:")
    print("  1. 使用非root用户运行容器")
    print("  2. 启用资源限制 (--memory, --cpus, --pids-limit)")
    print("  3. 丢弃所有capabilities (--cap-drop=ALL)")
    print("  4. 使用只读文件系统 (--read-only)")
    print("  5. 限制网络访问 (--network=none)")
