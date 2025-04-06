# 使用指南

## 基本用法

### 命令行参数

```
usage: vulnhuntr [-h] -r ROOT [-a ANALYZE] [-l {claude,gpt,ollama,deepseek}] [-v]

分析 GitHub 项目中的漏洞。运行前请导出相应的 API 密钥。

options:
  -h, --help            显示此帮助信息并退出
  -r ROOT, --root ROOT  项目的根目录路径
  -a ANALYZE, --analyze ANALYZE
                        要分析的项目中的特定路径或文件
  -l {claude,gpt,ollama,deepseek}, --llm {claude,gpt,ollama,deepseek}
                        要使用的 LLM 客户端（默认：claude）
  -v, --verbosity       增加输出详细程度（-v 为 INFO，-vv 为 DEBUG）
```

### 使用示例

#### 1. 分析整个仓库

使用 Claude 分析整个仓库：

```bash
export ANTHROPIC_API_KEY="your-api-key"
vulnhuntr -r /path/to/target/repo/
```

#### 2. 分析特定文件

使用 GPT-4 分析特定文件：

```bash
export OPENAI_API_KEY="your-api-key"
vulnhuntr -r /path/to/target/repo/ -a server.py -l gpt
```

#### 3. 使用 Deepseek 分析

使用 Deepseek 分析代码：

```bash
export DEEPSEEK_API_KEY="your-api-key"
export DEEPSEEK_BASE_URL="https://api.deepseek.com/v1"
vulnhuntr -r /path/to/target/repo/ -a server.py -l deepseek
```

#### 4. 使用 Docker 运行

使用 Claude 和自定义端点：

```bash
docker run --rm \
  -e ANTHROPIC_API_KEY=your-api-key \
  -e ANTHROPIC_BASE_URL=https://your-endpoint/api \
  -v /path/to/target/repo:/repo \
  vulnhuntr:latest \
  -r /repo \
  -a target-file.py
```

## 最佳实践

### 1. 选择分析目标

- 优先分析处理用户输入的文件
- 关注认证和授权相关的代码
- 检查文件上传和处理逻辑
- 审查 API 端点实现

### 2. 优化分析效率

- 使用 `-a` 参数指定具体文件或目录
- 从最可能包含漏洞的组件开始分析
- 使用 `-v` 参数获取详细日志
- 合理设置 LLM 的上下文窗口大小

### 3. 成本控制

- 设置 LLM 提供商的支出限制
- 使用较小的代码块进行分析
- 优先使用 Claude（效果更好）
- 避免重复分析相同的代码

## 输出说明

### 1. 分析报告结构

每个漏洞报告包含：
- 漏洞描述
- 漏洞类型
- 置信度分数
- 概念验证（PoC）
- 修复建议

### 2. 置信度分数说明

- < 7：不太可能存在漏洞
- 7：需要进一步调查
- 8+：很可能存在有效漏洞

### 3. 日志文件

- 位置：`vulhuntr.log`
- 内容：详细的分析过程
- 用途：调试和问题排查

## 常见问题

### 1. API 密钥问题

确保：
- 正确设置环境变量
- API 密钥有效且未过期
- 有足够的 API 调用额度
- 对于 Deepseek，确保设置了正确的 API 密钥和基础 URL

### 2. 分析超时

如果分析超时：
- 减小分析范围
- 检查网络连接
- 增加超时设置

### 3. 误报处理

处理误报：
- 检查置信度分数
- 验证 PoC 的有效性
- 调整分析参数 