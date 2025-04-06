<div align="center">

  <img width="250" src="https://github.com/user-attachments/assets/d1153ab4-df29-4955-ad49-1be7fad18bb3" alt="Vulnhuntr Logo">

一个使用 LLM 和静态代码分析来识别远程可利用漏洞的工具。

**全球首个自主 AI 发现的 0day 漏洞**

</div>

## 描述
Vulnhuntr 利用 LLM 的强大功能，自动创建和分析从远程用户输入到服务器输出的完整代码调用链，用于检测复杂的、多步骤的、绕过安全性的漏洞，这些漏洞远远超出了传统静态代码分析工具的能力范围。查看所有详细信息，包括所有 0-day 漏洞的 Vulnhuntr 输出：[Protect AI Vulnhuntr 博客](https://protectai.com/threat-research/vulnhuntr-first-0-day-vulnerabilities)

## 发现的漏洞

> [!TIP]
> 使用 Vulnhuntr 发现了漏洞？向 [huntr.com](https://huntr.com) 提交报告以获得 $$，并提交 PR 将其添加到下面的列表中！

> [!NOTE]
> 此表仅显示了迄今为止发现的部分漏洞。在负责任的披露期结束后，我们将取消编辑。

| 仓库 | Stars | 漏洞 |
| - | - | - |
| [gpt_academic](https://github.com/binary-husky/gpt_academic) | 67k | [LFI](https://nvd.nist.gov/vuln/detail/CVE-2024-10100), [XSS](https://nvd.nist.gov/vuln/detail/CVE-2024-10101) |
| [ComfyUI](https://github.com/comfyanonymous/ComfyUI) | 66k | [XSS](https://nvd.nist.gov/vuln/detail/CVE-2024-10099) |
| [Langflow](https://github.com/langflow-ai/langflow) | 46k | RCE, IDOR |
| [FastChat](https://github.com/lm-sys/FastChat) | 37k | [SSRF](https://nvd.nist.gov/vuln/detail/CVE-2024-10044) | 
| [Ragflow](https://github.com/infiniflow/ragflow) | 31k | [RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-10131) |
| [LLaVA](https://github.com/haotian-liu/LLaVA) | 21k | [SSRF](https://www.cve.org/CVERecord?id=CVE-2024-9309) |
| [gpt-researcher](https://github.com/assafelovic/gpt-researcher) | 17k | [AFO](https://github.com/assafelovic/gpt-researcher/pull/935) |
| [Letta](https://github.com/letta-ai/letta) | 14k | [AFO](https://github.com/letta-ai/letta/pull/2067) | 

## 限制

- 仅支持 Python 代码库。
- 只能识别以下漏洞类型：
  - 本地文件包含 (LFI)
  - 任意文件覆盖 (AFO)
  - 远程代码执行 (RCE)
  - 跨站脚本 (XSS)
  - SQL 注入 (SQLI)
  - 服务器端请求伪造 (SSRF)
  - 不安全的直接对象引用 (IDOR)

## 安装

> [!IMPORTANT]
> Vulnhuntr 严格要求 Python 3.10，因为它使用的 Jedi 解析器在该版本中存在一些 bug。如果使用其他版本的 Python 安装，它将无法可靠工作。

我们建议使用 [pipx](https://github.com/pypa/pipx) 或 Docker 来轻松安装和运行 Vulnhuntr。

使用 Docker：
```bash
docker build -t vulnhuntr https://github.com/protectai/vulnhuntr.git#main
```

## 使用方法

此工具设计用于分析 GitHub 仓库中潜在的远程可利用漏洞。该工具需要 API 密钥和 GitHub 仓库的本地路径。您也可以选择性地指定 LLM 服务的自定义端点。

> [!CAUTION]
> 始终为您使用的 LLM 提供商设置支出限制或密切监控成本。此工具可能会产生高额账单，因为它会尝试在 LLM 的上下文窗口中放入尽可能多的代码。

> [!TIP]
> 我们建议使用 Claude 作为 LLM。通过测试，我们发现它的效果比 GPT 更好。

### 命令行界面

```
usage: vulnhuntr [-h] -r ROOT [-a ANALYZE] [-l {claude,gpt,ollama}] [-v]

分析 GitHub 项目中的漏洞。运行前请导出 ANTHROPIC_API_KEY/OPENAI_API_KEY。

options:
  -h, --help            显示此帮助信息并退出
  -r ROOT, --root ROOT  项目的根目录路径
  -a ANALYZE, --analyze ANALYZE
                        要分析的项目中的特定路径或文件
  -l {claude,gpt,ollama}, --llm {claude,gpt,ollama}
                        要使用的 LLM 客户端（默认：claude）
  -v, --verbosity       增加输出详细程度（-v 为 INFO，-vv 为 DEBUG）
```



*实验性*

Ollama 作为选项已包含，但我们尚未成功让开源模型正确构建其输出。

```bash
export OLLAMA_BASE_URL=http://localhost:11434/api/generate
export OLLAMA_MODEL=llama3.2
vulnhuntr -r /path/to/target/repo/ -a server.py -l ollama
``` 

## 逻辑流程
![VulnHuntr logic](https://github.com/user-attachments/assets/7757b053-36ff-425e-ab3d-ab0100c81d49)
- LLM 总结 README 并将其包含在系统提示中
- LLM 对整个文件进行初步分析并报告任何潜在的漏洞
- Vulnhuntr 然后给 LLM 一个特定于漏洞的提示进行二次分析
- 每次 LLM 分析代码时，它都会请求来自项目中其他文件的额外上下文函数/类/变量
- 它继续这样做，直到从用户输入到服务器处理的整个调用链完成，然后给出最终分析
- 最终分析包括其推理、概念验证漏洞利用和置信度分数

>[!TIP]
> 通常置信度分数 < 7 意味着不太可能存在漏洞。置信度分数为 7 意味着应该进行调查，置信度分数为 8+ 意味着很可能存在有效漏洞。

## 输出

该工具生成一个详细的分析报告，包括：

- 每个文件的初步评估结果
- 包含上下文函数和类引用的二次评估结果
- 发现的漏洞的置信度分数
- 分析过程的日志
- PoC 漏洞利用

以下是 Vulnhuntr 报告的示例，描述了在 [Ragflow](https://github.com/infiniflow/ragflow) 中发现的 0-day 远程代码执行漏洞（现已修复）：

```
scratchpad:
  1. 分析 llm_app.py 中的 add_llm 函数。2. 识别出用户输入用作访问字典的键：EmbeddingModel、ChatModel、RerankModel、
CvModel 和 TTSModel。3. 这些字典包含类引用，这些类使用用户提供的参数进行实例化。4. factory 变量直接从用户输入（req['llm_factory']）使用，没有适当的验证。5. llm_name 在大多数情况下也是从用户输入派生的。6. 这些类的实例化发生在 try-except 块中，但异常仅用于错误消息，而不是防止执行。7. api_key 和其他敏感信息直接传递给这些实例化的类。8. 对 factory 或 llm_name 变量没有全面的输入验证或清理。9. 漏洞位于用 @login_required 装饰的路由中，表明它对认证用户可访问。10.
审查 EmbeddingModel、ChatModel、RerankModel、CvModel 和 TTSModel 字典以了解其内容和潜在的利用可能性。
----------------------------------------

analysis:
  llm_app.py 中的 add_llm 函数包含一个严重的远程代码执行 (RCE) 漏洞。该函数使用用户提供的输入（req['llm_factory'] 和 req['llm_name']）来动态实例化来自 EmbeddingModel、ChatModel、RerankModel、CvModel 和 TTSModel 字典的类。这种使用用户输入作为键来访问和实例化类的模式本质上是危险的，因为它允许攻击者可能执行任意代码。由于对这些用户提供的值缺乏全面的输入验证或清理，漏洞变得更加严重。虽然有一些特定工厂类型的检查，但它们并不全面，可以被绕过。攻击者可能提供 'llm_factory' 的恶意值，当用作这些模型字典的索引时，导致执行任意代码。该漏洞特别严重，因为它发生在用 @login_required 装饰的路由中，表明它对认证用户可访问，这可能会给人一种虚假的安全感。
----------------------------------------

poc:
  POST /add_llm HTTP/1.1
  Host: target.com
  Content-Type: application/json
  Authorization: Bearer <valid_token>
  
  {
      "llm_factory": "__import__('os').system",
      "llm_name": "id",
      "model_type": "EMBEDDING",
      "api_key": "dummy_key"
  }
  
  此有效负载通过将 'llm_factory' 设置为一个字符串来尝试利用漏洞，该字符串在评估时会导入 os 模块并调用 system。'llm_name' 设置为 'id'，如果漏洞利用成功，它将作为系统命令执行。
----------------------------------------

confidence_score:
  8
----------------------------------------

vulnerability_types:
  - RCE
----------------------------------------
```

## 日志记录

该工具在名为 `vulhuntr.log` 的文件中记录分析过程和结果。此文件包含每个分析步骤的详细信息，包括初步和二次评估。



