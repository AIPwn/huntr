# Vulnhuntr 文档

## 文档目录

### 入门指南
- [安装指南](installation.md) - 如何安装和配置 Vulnhuntr
- [使用指南](usage.md) - 如何使用 Vulnhuntr 进行漏洞分析
- [漏洞类型说明](vulnerability-types.md) - 支持的漏洞类型及其特征

### 开发指南
- [贡献指南](contributing.md) - 如何参与项目开发
- [更新日志](CHANGELOG.md) - 版本更新历史

## 快速开始

1. 安装 Vulnhuntr：
```bash
pipx install git+https://github.com/protectai/vulnhuntr.git --python python3.10
```

2. 配置环境变量：
```bash
export ANTHROPIC_API_KEY="your-api-key"
```

3. 运行分析：
```bash
vulnhuntr -r /path/to/target/repo/
```

## 文档更新

如果您发现文档中的任何问题或需要改进，请：

1. Fork 项目
2. 创建新分支
3. 提交更改
4. 创建 Pull Request

## 获取帮助

如果您在使用过程中遇到问题：

1. 查看 [常见问题](usage.md#常见问题)
2. 检查 [更新日志](CHANGELOG.md)
3. 提交 Issue

## 联系我们

- 项目维护者：Dan McInerney (dan@protectai.com)
- 项目主页：[GitHub](https://github.com/protectai/vulnhuntr)
- 问题反馈：[Issues](https://github.com/protectai/vulnhuntr/issues) 