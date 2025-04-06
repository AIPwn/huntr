# 安装指南

## 系统要求

- Python 3.10（必需）
- Git
- Docker（可选，用于容器化部署）

## 安装方法

### 1. 使用 pipx 安装（推荐）

```bash
pipx install git+https://github.com/protectai/vulnhuntr.git --python python3.10
```

### 2. 使用 Docker 安装

```bash
docker build -t vulnhuntr https://github.com/protectai/vulnhuntr.git#main
```

### 3. 从源代码安装

```bash
git clone https://github.com/protectai/vulnhuntr
cd vulnhuntr
poetry install
```

## 环境配置

1. 复制环境变量模板：
```bash
cp .env.example .env
```

2. 配置必要的环境变量：
- `ANTHROPIC_API_KEY`：如果使用 Claude
- `OPENAI_API_KEY`：如果使用 GPT
- `OLLAMA_BASE_URL`：如果使用 Ollama（实验性）
- `DEEPSEEK_API_KEY`：如果使用 Deepseek
- `DEEPSEEK_BASE_URL`：Deepseek API 的基础 URL（可选，默认为 https://api.deepseek.com/v1）

## 验证安装

运行以下命令验证安装是否成功：

```bash
vulnhuntr --help
```

## 常见问题

### 1. Python 版本问题

如果遇到 Python 版本相关的错误，请确保：
- 使用 Python 3.10
- 如果使用 pyenv，可以运行：`pyenv install 3.10.0 && pyenv global 3.10.0`

### 2. 依赖安装失败

如果依赖安装失败，可以尝试：
- 更新 pip：`pip install --upgrade pip`
- 清理 pip 缓存：`pip cache purge`
- 使用国内镜像源：`pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple`

### 3. Docker 构建失败

如果 Docker 构建失败，请确保：
- Docker 服务正在运行
- 有足够的磁盘空间
- 网络连接正常

### 4. Deepseek API 配置问题

如果使用 Deepseek 遇到问题，请确保：
- API 密钥格式正确
- 基础 URL 可访问
- 有足够的 API 调用额度
- 网络连接正常 