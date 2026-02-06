# 安全配置指南

## 🔐 重要安全提醒

本项目已移除所有硬编码的敏感信息。请务必按照以下指南配置环境变量。

## 快速开始

### 1. 配置环境变量

```bash
# 复制环境变量模板
cp .env.example .env

# 编辑 .env 文件，填入你的 API 密钥
nano .env  # 或 vim/code .env
```

### 2. 配置文件

```bash
# 复制配置文件模板
cp config.yaml.template config.yaml

# 配置文件已使用环境变量引用，通常不需要修改
# 除非你需要覆盖特定配置
```

### 3. 安装依赖

```bash
# Python 项目
pip install python-dotenv pyyaml

# Node.js 项目
npm install dotenv js-yaml
```

## 环境变量说明

### 必需的环境变量

| 变量名 | 说明 | 获取方式 |
|--------|------|----------|
| `GEMINI_API_KEY` | Google Gemini API 密钥 | [Google AI Studio](https://makersuite.google.com/app/apikey) |

### 可选的环境变量

| 变量名 | 说明 | 用途 |
|--------|------|------|
| `OPENAI_API_KEY` | OpenAI API 密钥 | GPT 模型支持 |
| `ANTHROPIC_API_KEY` | Anthropic API 密钥 | Claude 模型支持 |
| `TELEGRAM_BOT_TOKEN` | Telegram Bot Token | Telegram 集成 |
| `DISCORD_BOT_TOKEN` | Discord Bot Token | Discord 集成 |
| `ELEVENLABS_API_KEY` | ElevenLabs API 密钥 | 语音合成功能 |
| `BRAVE_API_KEY` | Brave Search API 密钥 | 搜索功能 |

## 安全最佳实践

### ✅ 应该做的

1. **使用 .env 文件**: 将所有敏感信息存放在 `.env` 文件中
2. **不要提交 .env**: `.env` 文件已在 `.gitignore` 中配置
3. **定期轮换密钥**: 建议每 3-6 个月更换一次 API 密钥
4. **限制密钥权限**: 为 API 密钥设置最小权限原则
5. **监控使用情况**: 定期检查 API 使用日志

### ❌ 不应该做的

1. **不要**在代码中硬编码 API 密钥
2. **不要**将 `.env` 文件提交到版本控制
3. **不要**在日志中打印敏感信息
4. **不要**分享你的 `.env` 文件
5. **不要**在公共仓库中包含真实密钥

## 故障排查

### 环境变量未加载

```python
# Python 示例
from dotenv import load_dotenv
import os

# 加载环境变量
load_dotenv()

# 验证是否加载成功
api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    print("错误: GEMINI_API_KEY 未设置")
    print("请检查 .env 文件是否存在并包含该变量")
```

### 配置文件解析失败

```python
import os
import yaml

# 读取配置文件并替换环境变量
with open('config.yaml', 'r') as f:
    config_content = f.read()
    # 替换环境变量占位符
    config_content = os.path.expandvars(config_content)
    config = yaml.safe_load(config_content)
```

## 密钥泄露应急处理

如果你不小心提交了包含真实密钥的文件：

1. **立即撤销密钥**: 到对应服务商控制台撤销该密钥
2. **生成新密钥**: 创建新的 API 密钥
3. **更新配置**: 在 `.env` 文件中更新为新密钥
4. **清理历史**: 使用 `git filter-branch` 或 BFG Repo-Cleaner 清理提交历史

```bash
# 示例: 使用 git filter-branch 移除敏感文件
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch config.yaml" \
  --prune-empty --tag-name-filter cat -- --all

# 清理和强制推送
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push origin --force --all
```

## 更多信息

- [Google AI Studio 文档](https://ai.google.dev/)
- [12-Factor App 配置管理](https://12factor.net/config)
- [OWASP 密钥管理最佳实践](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)

---

⚠️ **请记住**: 保护 API 密钥就是保护你的账户安全和财产安全！
