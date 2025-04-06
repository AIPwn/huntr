# Vulnhuntr Web UI 文档

## 简介

Vulnhuntr Web UI 是一个基于 FastAPI 和 Bootstrap 5 构建的 Web 界面,用于分析 Python 代码中的安全漏洞。它提供了一个直观的用户界面,让用户可以方便地使用不同的 LLM 模型来分析代码。

## 功能特点

1. 支持多种 LLM 模型:
   - Claude
   - ChatGPT 
   - Ollama
   - Deepseek

2. 分析功能:
   - 支持分析整个仓库
   - 支持分析指定文件或目录
   - 实时显示分析结果
   - 根据漏洞严重程度显示不同颜色标识

3. 用户界面:
   - 响应式设计,支持移动端访问
   - 简洁直观的操作界面
   - 清晰的结果展示

## 安装说明

1. 安装依赖:
```bash
pip install -r requirements.txt
```

2. 运行服务器:
```bash
python web/main.py
```

3. 访问 Web UI:
打开浏览器访问 `http://localhost:8000`

## 使用说明

### 基本操作

1. 输入仓库路径:
   - 在"仓库路径"输入框中输入要分析的 Python 项目路径
   - 路径可以是相对路径或绝对路径

2. 选择分析范围(可选):
   - 在"分析路径"输入框中输入具体的文件或目录
   - 留空则分析整个仓库

3. 选择 LLM 模型:
   - 从下拉菜单中选择要使用的 LLM 模型
   - 默认使用 Claude

4. 开始分析:
   - 点击"开始分析"按钮
   - 等待分析完成

### 分析结果

分析结果会显示在右侧面板中,包括:

1. 文件信息:
   - 显示被分析的文件路径

2. 漏洞信息:
   - 漏洞严重程度(高/中/低)
   - 漏洞分析说明
   - 修复建议

3. 颜色标识:
   - 红色: 高危漏洞
   - 黄色: 中危漏洞
   - 绿色: 低危漏洞

## API 文档

访问 `http://localhost:8000/docs` 可以查看完整的 API 文档。

### 主要接口

1. 主页接口:
```
GET /
```
返回 Web UI 主页

2. 分析接口:
```
POST /api/analyze
```
请求体:
```json
{
    "repo_path": "仓库路径",
    "analyze_path": "分析路径(可选)",
    "llm_type": "llm类型"
}
```

## 注意事项

1. 环境变量设置:
   - 使用 Claude 需要设置 `ANTHROPIC_API_KEY`
   - 使用 ChatGPT 需要设置 `OPENAI_API_KEY`
   - 使用 Deepseek 需要设置 `DEEPSEEK_API_KEY`

2. 文件大小限制:
   - 单个文件最大支持 16MB

3. 性能考虑:
   - 分析大型仓库可能需要较长时间
   - 建议先分析关键文件

## 错误处理

1. 常见错误:
   - 仓库路径不存在
   - API 密钥未设置
   - 文件读取权限问题

2. 错误提示:
   - 界面会显示具体的错误信息
   - 日志文件记录详细错误信息

## 日志

- 日志文件: `vulnhuntr.log`
- 日志级别: INFO
- 记录内容: 分析过程、错误信息等

## 开发说明

### 技术栈

1. 后端:
   - FastAPI
   - Pydantic
   - Uvicorn

2. 前端:
   - Bootstrap 5
   - JavaScript
   - CodeMirror

### 目录结构

```
web/
├── main.py          # FastAPI 应用主文件
├── static/          # 静态文件目录
└── templates/       # 模板文件目录
    └── index.html   # 主页模板
```

## 贡献指南

1. 提交 Issue:
   - 描述问题或建议
   - 提供复现步骤
   - 附上相关日志

2. 提交 PR:
   - 遵循代码规范
   - 添加必要的测试
   - 更新文档

## 许可证

本项目采用 MIT 许可证。详见 LICENSE 文件。 