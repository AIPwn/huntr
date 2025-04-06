import json
import re
import argparse
import structlog
from vulnhuntr.symbol_finder import SymbolExtractor
from vulnhuntr.LLMs import Claude, ChatGPT, Ollama, Deepseek
from vulnhuntr.prompts import *
from vulnhuntr.prompts import SYS_PROMPT_TEMPLATE as SYSTEM_PROMPT
from rich import print
from typing import List, Generator
from enum import Enum
from pathlib import Path
from pydantic_xml import BaseXmlModel, element
from pydantic import BaseModel, Field
import dotenv
import os
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import logging
import datetime
import time
import subprocess
import tempfile
import shutil
import re
import uuid
import platform

__version__ = "1.0.0"
__author__ = "Vulnhuntr Team"

print(f"[bold green]Vulnhuntr v{__version__}[/bold green] - Python Code Vulnerability Analysis Tool")
print("[bold]-------------------------------------------------------------------[/bold]")

dotenv.load_dotenv()

# 设置日志目录
app_dir = Path(os.path.dirname(os.path.abspath(__file__)))
logs_dir = app_dir / "logs"
reports_dir = app_dir / "reports"
task_logs_dir = app_dir / "task_logs"
# 添加克隆仓库存放目录
cloned_repos_dir = app_dir / "cloned_repos"

# 确保目录存在
os.makedirs(logs_dir, exist_ok=True)
os.makedirs(reports_dir, exist_ok=True)
os.makedirs(task_logs_dir, exist_ok=True)
os.makedirs(cloned_repos_dir, exist_ok=True)

# 配置日志
log_dir = logs_dir
log_dir.mkdir(exist_ok=True)
log_file = log_dir / "vulnhuntr.log"

# 设置文件日志处理器
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.INFO)

# 设置控制台日志处理器
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)

# 配置日志格式
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(log_formatter)
console_handler.setFormatter(log_formatter)

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.PrintLoggerFactory(),
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    cache_logger_on_first_use=True,
)

# 获取日志记录器
log = structlog.get_logger("vulnhuntr")

# 添加文件处理器
for handler in [file_handler, console_handler]:
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

import faulthandler
faulthandler.enable()

# 创建任务日志目录
task_logs_dir = task_logs_dir
task_logs_dir.mkdir(exist_ok=True)

# 任务日志记录器类
class TaskLogger:
    """为每个分析任务创建独立的日志记录器"""
    
    def __init__(self, task_id: str, repo_path: str, llm_type: str):
        """初始化任务日志记录器
        
        Args:
            task_id: 任务唯一标识符
            repo_path: 分析的仓库路径
            llm_type: 使用的LLM类型
        """
        self.task_id = task_id
        self.repo_path = repo_path
        self.llm_type = llm_type
        
        # 创建时间戳
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 创建日志文件
        self.log_file = task_logs_dir / f"task_{task_id}_{self.timestamp}.log"
        
        # 配置文件处理器
        self.file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        self.file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        # 创建记录器
        self.logger = logging.getLogger(f"task_{task_id}")
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self.file_handler)
        
        # 确保记录器不会传播到根记录器
        self.logger.propagate = False
        
        # 记录初始化信息
        self.info(f"任务日志初始化 - 任务ID: {task_id}")
        self.info(f"仓库路径: {repo_path}")
        self.info(f"LLM类型: {llm_type}")
        self.info(f"操作系统: {platform.platform()}")
        self.info(f"Python版本: {platform.python_version()}")
        self.info(f"日志文件: {self.log_file}")
    
    def info(self, message: str):
        """记录信息级别的消息"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """记录警告级别的消息"""
        self.logger.warning(message)
    
    def error(self, message: str, exc_info=False):
        """记录错误级别的消息
        
        Args:
            message: 错误消息
            exc_info: 是否包含异常信息
        """
        self.logger.error(message, exc_info=exc_info)
    
    def log_file_analysis(self, file_path: Path, file_size: int, status: str, error_message: str = None):
        """记录文件分析结果
        
        Args:
            file_path: 文件路径
            file_size: 文件大小（字节）
            status: 分析状态，可以是 'success'、'skipped' 或 'error'
            error_message: 如果状态是 'error' 或 'skipped'，则为错误消息
        """
        file_info = {
            "file_path": str(file_path),
            "file_size_bytes": file_size,
            "file_size_mb": file_size / (1024 * 1024),
            "status": status
        }
        
        if error_message:
            file_info["error_message"] = error_message
        
        self.info(f"文件分析 - {json.dumps(file_info, ensure_ascii=False)}")
    
    def log_vulnerability(self, file_path: Path, vulnerability_types: List[str], confidence_score: float):
        """记录检测到的漏洞
        
        Args:
            file_path: 存在漏洞的文件路径
            vulnerability_types: 漏洞类型列表
            confidence_score: 置信度分数
        """
        vuln_info = {
            "file_path": str(file_path),
            "vulnerability_types": vulnerability_types,
            "confidence_score": confidence_score
        }
        
        self.info(f"发现漏洞 - {json.dumps(vuln_info, ensure_ascii=False)}")
    
    def log_report_generated(self, report_path: Path):
        """记录报告生成信息
        
        Args:
            report_path: 报告文件路径
        """
        self.info(f"生成报告 - 路径: {report_path}")
    
    def log_task_completed(self, analyzed_count: int, skipped_count: int):
        """记录任务完成信息
        
        Args:
            analyzed_count: 已分析文件数量
            skipped_count: 已跳过文件数量
        """
        completion_info = {
            "status": "completed",
            "analyzed_count": analyzed_count,
            "skipped_count": skipped_count,
            "total_count": analyzed_count + skipped_count,
            "completion_time": datetime.datetime.now().isoformat()
        }
        
        self.info(f"任务完成 - {json.dumps(completion_info, ensure_ascii=False)}")
    
    def log_task_failed(self, error_message: str):
        """记录任务失败信息
        
        Args:
            error_message: 错误消息
        """
        failure_info = {
            "status": "failed",
            "error_message": error_message,
            "failure_time": datetime.datetime.now().isoformat()
        }
        
        self.error(f"任务失败 - {json.dumps(failure_info, ensure_ascii=False)}")

def generate_report_filename(repo_path):
    """Generate a report filename based on repository path and current time"""
    repo_name = Path(repo_path).name or "unknown_repo"
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return f"vulnhuntr_report_{repo_name}_{timestamp}.txt"

def write_vulnerability_report(report_path, analyzed_files, skipped_files=None):
    """Write vulnerability analysis results to a report file"""
    try:
        # 确保报告目录存在
        report_dir = os.path.dirname(report_path)
        os.makedirs(report_dir, exist_ok=True)
        
        log.info(f"正在写入漏洞报告到: {report_path}")
        
        # 如果是克隆的仓库，获取基础路径用于转换为相对路径
        base_path = None
        if analyzed_files and 'file_path' in analyzed_files[0]:
            first_file_path = analyzed_files[0]['file_path']
            # 检查是否来自克隆的仓库
            if str(cloned_repos_dir) in first_file_path:
                # 找到仓库根目录（克隆目录的下一级目录）
                parts = Path(first_file_path).parts
                clone_index = parts.index(cloned_repos_dir.name)
                if len(parts) > clone_index + 1:
                    base_path = str(Path(*parts[:clone_index+2]))
                    log.info(f"检测到克隆仓库，基础路径: {base_path}")
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write(f"VULNHUNTR VULNERABILITY REPORT\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            # Write analysis for each file
            for file_data in analyzed_files:
                file_path = file_data['file_path']
                response = file_data['response']
                
                # 转换为相对路径
                display_path = file_path
                if base_path and file_path.startswith(base_path):
                    # 移除基础路径，保留相对路径部分
                    display_path = file_path[len(base_path)+1:]
                elif '/' in file_path:
                    # 如果没有检测到克隆仓库但有路径分隔符，则取最后一个组件作为文件名
                    display_path = Path(file_path).name
                
                f.write(f"FILE: {display_path}\n")
                f.write("-"*80 + "\n")
                
                f.write("ANALYSIS:\n")
                f.write(f"{response.analysis}\n\n")
                
                if response.vulnerability_types:
                    f.write("VULNERABILITY TYPES:\n")
                    for vuln_type in response.vulnerability_types:
                        f.write(f"- {vuln_type}\n")
                    f.write("\n")
                
                if response.poc:
                    f.write("PROOF OF CONCEPT:\n")
                    f.write(f"{response.poc}\n\n")
                
                f.write(f"CONFIDENCE SCORE: {response.confidence_score}/10\n\n")
                
                if response.context_code:
                    f.write("RELEVANT CODE CONTEXT:\n")
                    for ctx in response.context_code:
                        f.write(f"- {ctx.name}: {ctx.reason}\n")
                        f.write(f"  {ctx.code_line}\n")
                    f.write("\n")
                
                f.write("="*80 + "\n\n")
            
            # Summary section
            f.write("SUMMARY\n")
            f.write("-"*80 + "\n")
            f.write(f"Total files analyzed: {len(analyzed_files)}\n")
            
            if skipped_files:
                f.write(f"Files skipped: {len(skipped_files)}\n")
                if len(skipped_files) > 0:
                    f.write("Skipped files:\n")
                    for skipped in skipped_files:
                        # 转换跳过的文件路径为相对路径
                        display_skipped = skipped
                        if base_path and skipped.startswith(base_path):
                            display_skipped = skipped[len(base_path)+1:]
                        elif '/' in skipped:
                            display_skipped = Path(skipped).name
                        f.write(f"- {display_skipped}\n")
                    f.write("\n")
            
            # Count vulnerabilities by type
            all_vulns = []
            for file_data in analyzed_files:
                all_vulns.extend(file_data['response'].vulnerability_types)
            
            vuln_counts = {}
            for v in all_vulns:
                vuln_counts[v] = vuln_counts.get(v, 0) + 1
            
            if vuln_counts:
                f.write("Vulnerability distribution:\n")
                for v_type, count in vuln_counts.items():
                    f.write(f"- {v_type}: {count}\n")
            else:
                f.write("No vulnerabilities found.\n")
        
        # 检查确保文件写入成功
        if not os.path.exists(report_path):
            log.error(f"报告文件创建失败: {report_path}")
            return None
            
        log.info(f"漏洞报告成功写入: {report_path}")
        return report_path
    
    except Exception as e:
        log.error(f"写入漏洞报告时出错: {str(e)}")
        # 返回None表示失败
        return None

class VulnType(str, Enum):
    LFI = "LFI"  # Local File Inclusion
    RCE = "RCE"  # Remote Code Execution
    SSRF = "SSRF"  # Server-Side Request Forgery
    AFO = "AFO"  # Arbitrary File Operation
    SQLI = "SQLI"  # SQL Injection
    XSS = "XSS"  # Cross-Site Scripting
    IDOR = "IDOR"  # Insecure Direct Object Reference
    CMDI = "CMDI"  # Command Injection
    AFD = "AFD"  # Arbitrary File Deletion
    AFW = "AFW"  # Arbitrary File Write
    AFR = "AFR"  # Arbitrary File Read
    PATH = "PATH"  # Path Traversal
    CSRF = "CSRF"  # Cross-Site Request Forgery
    XXE = "XXE"  # XML External Entity
    DESERIALIZATION = "DESERIALIZATION"  # Insecure Deserialization
    BROKEN_AUTH = "BROKEN_AUTH"  # Broken Authentication
    INFO_LEAK = "INFO_LEAK"  # Information Leak
    INSECURE_CONFIG = "INSECURE_CONFIG"  # Insecure Configuration
    OPEN_REDIRECT = "OPEN_REDIRECT"  # Open Redirect
    UNKNOWN = "UNKNOWN"  # Unknown vulnerability type

class ContextCode(BaseModel):
    name: str = Field(description="Function or Class name")
    reason: str = Field(description="Brief reason why this function's code is needed for analysis")
    code_line: str = Field(description="The single line of code where where this context object is referenced.")

class Response(BaseModel):
    scratchpad: str = Field(description="Your step-by-step analysis process. Output in plaintext with no line breaks.")
    analysis: str = Field(description="Your final analysis. Output in plaintext with no line breaks.")
    poc: str = Field(description="Proof-of-concept exploit, if applicable.")
    confidence_score: int = Field(description="0-10, where 0 is no confidence and 10 is absolute certainty because you have the entire user input to server output code path.")
    vulnerability_types: List[VulnType] = Field(description="The types of identified vulnerabilities")
    context_code: List[ContextCode] = Field(description="List of context code items requested for analysis, one function or class name per item. No standard library or third-party package code.")

class AnalyzeRequest(BaseModel):
    repo_path: str = Field(description="Repository path to analyze")
    analyze_path: str | None = Field(description="Specific file or directory path to analyze", default=None)
    llm_type: str = Field(description="LLM type to use", default="claude")

class ReadmeContent(BaseXmlModel, tag="readme_content"):
    content: str

class ReadmeSummary(BaseXmlModel, tag="readme_summary"):
    readme_summary: str

class Instructions(BaseXmlModel, tag="instructions"):
    instructions: str

class ResponseFormat(BaseXmlModel, tag="response_format"):
    response_format: str

class AnalysisApproach(BaseXmlModel, tag="analysis_approach"):
    analysis_approach: str

class Guidelines(BaseXmlModel, tag="guidelines"):
    guidelines: str

class FileCode(BaseXmlModel, tag="file_code"):
    file_path: str = element()
    file_source: str = element()

class PreviousAnalysis(BaseXmlModel, tag="previous_analysis"):
    previous_analysis: str

class ExampleBypasses(BaseXmlModel, tag="example_bypasses"):
    example_bypasses: str

class CodeDefinition(BaseXmlModel, tag="code"):
    name: str = element()
    context_name_requested: str = element()
    file_path: str = element()
    source: str = element()

class CodeDefinitions(BaseXmlModel, tag="context_code"):
    definitions: List[CodeDefinition] = []

class RepoOps:
    def __init__(self, repo_path: Path | str) -> None:
        self.repo_path = Path(repo_path).resolve()  # 转换为绝对路径
        self.to_exclude = {'/setup.py', '/test', '/example', '/docs', '/site-packages', '.venv', 'virtualenv', '/dist'}
        self.file_names_to_exclude = ['test_', 'conftest', '_test.py']
        log.debug(f"Initializing RepoOps, repository path: {self.repo_path}")

    def get_files_to_analyze(self, analyze_path: Path | None = None) -> List[Path]:
        try:
            path_to_analyze = analyze_path or self.repo_path
            path_to_analyze = path_to_analyze.resolve()  # 转换为绝对路径
            log.debug(f"Starting to find files, analysis path: {path_to_analyze}")
            
            if path_to_analyze.is_file():
                log.debug(f"Found single file: {path_to_analyze}")
                return [path_to_analyze]
            elif path_to_analyze.is_dir():
                files = []
                for file_path in path_to_analyze.rglob('*.py'):
                    # 检查文件是否应该被排除
                    file_str = str(file_path).replace('\\', '/')
                    if any(exclude in file_str for exclude in self.to_exclude):
                        log.debug(f"Excluding file: {file_path}")
                        continue
                    if any(fn in file_path.name for fn in self.file_names_to_exclude):
                        log.debug(f"Excluding test file: {file_path}")
                        continue
                    files.append(file_path)
                
                log.debug(f"Found {len(files)} Python files in directory")
                return files
            else:
                error_msg = f"Specified analysis path does not exist: {path_to_analyze}"
                log.error(error_msg)
                raise FileNotFoundError(error_msg)
        except Exception as e:
            log.error(f"Error finding files: {str(e)}")
            raise

def extract_between_tags(tag: str, string: str, strip: bool = False) -> list[str]:
    """
    https://github.com/anthropics/anthropic-cookbook/blob/main/misc/how_to_enable_json_mode.ipynb
    """
    ext_list = re.findall(f"<{tag}>(.+?)</{tag}>", string, re.DOTALL)
    if strip:
        ext_list = [e.strip() for e in ext_list]
    return ext_list

def initialize_llm(llm_arg: str, system_prompt: str = "") -> Claude | ChatGPT | Ollama | Deepseek:
    """Initialize LLM client"""
    if llm_arg == "claude":
        return Claude(
            model="claude-3-sonnet-20240229",
            base_url="https://api.anthropic.com",
            system_prompt=system_prompt or SYSTEM_PROMPT
        )
    elif llm_arg == "chatgpt":
        return ChatGPT(
            model="gpt-4-turbo-preview",
            base_url="https://api.openai.com/v1",
            system_prompt=system_prompt or SYSTEM_PROMPT
        )
    elif llm_arg == "ollama":
        return Ollama(
            model="mistral",
            base_url="http://localhost:11434/api/generate",
            system_prompt=system_prompt or SYSTEM_PROMPT
        )
    elif llm_arg == "deepseek":
        return Deepseek(
            model="deepseek-chat",
            base_url="https://api.deepseek.com/v1",
            system_prompt=system_prompt or SYSTEM_PROMPT
        )
    else:
        raise ValueError(f"Unsupported LLM type: {llm_arg}")

def print_readable(report: Response) -> None:
    """Print readable report"""
    print(f"\n[bold green]Analysis Process:[/bold green]\n{report.scratchpad}")
    print(f"\n[bold green]Analysis Result:[/bold green]\n{report.analysis}")
    if report.poc:
        print(f"\n[bold green]POC:[/bold green]\n{report.poc}")
    print(f"\n[bold green]Confidence:[/bold green] {report.confidence_score}/10")
    print(f"\n[bold green]Vulnerability Types:[/bold green] {', '.join(report.vulnerability_types)}")

def run_cli(repo_path: str | None = None, analyze_path: str | None = None, llm_type: str = "claude"):
    """Run in CLI mode"""
    # 生成任务ID
    task_id = str(uuid.uuid4())[:8]
    
    try:
        # If repo_path is a GitHub URL, clone it to the cloned_repos directory
        cloned_dir = None
        if repo_path and is_github_url(repo_path):
            try:
                cloned_dir = clone_github_repo(repo_path)
                repo_path = cloned_dir
            except Exception as e:
                log.error(f"Failed to clone GitHub repository: {str(e)}")
                print(f"[bold red]Failed to clone GitHub repository: {str(e)}[/bold red]")
                return
            
        # If no repository path is provided, use the current directory
        if not repo_path:
            repo_path = os.getcwd()
            log.info(f"No repository path provided, using current directory: {repo_path}")
            
        # 创建任务日志记录器
        task_logger = TaskLogger(task_id, repo_path, llm_type)
            
        log.info(f"Starting repository analysis: {repo_path}")
        task_logger.info("Starting repository analysis")
        
        repo_ops = RepoOps(repo_path)
        files_to_analyze = repo_ops.get_files_to_analyze(
            Path(analyze_path) if analyze_path else None
        )
        
        if not files_to_analyze:
            log.warning(f"No Python files found in directory {repo_path}")
            task_logger.warning(f"No Python files found in directory {repo_path}")
            print(f"[bold yellow]Warning: No Python files found in directory {repo_path}[/bold yellow]")
            # 注意：现在我们保留克隆的仓库，不再自动删除
            
            task_logger.log_task_failed("No Python files found")
            return
            
        log.info(f"Found {len(files_to_analyze)} files to analyze")
        task_logger.info(f"Found {len(files_to_analyze)} files to analyze")
        
        log.info(f"Initializing LLM: {llm_type}")
        task_logger.info(f"Initializing LLM: {llm_type}")
        llm = initialize_llm(llm_type)
        
        # Get valid vulnerability types as a string for the prompt
        valid_vuln_types = ", ".join([t.name for t in VulnType])
        task_logger.info(f"Using vulnerability types: {valid_vuln_types}")
        
        # List to store analysis results for report generation
        analyzed_files = []
        skipped_files = []
        
        for file_path in files_to_analyze:
            print(f"\n[bold blue]Analyzing file:[/bold blue] {file_path}")
            log.info(f"Analyzing file: {file_path}")
            task_logger.info(f"Starting analysis of file: {file_path}")
            
            try:
                # Check file size before analyzing
                file_size = file_path.stat().st_size
                file_size_mb = file_size / (1024 * 1024)
                task_logger.info(f"File size: {file_size} bytes ({file_size_mb:.2f} MB)")
                
                # Skip files larger than 1MB to avoid timeouts
                if file_size_mb > 1:
                    log.warning(f"Skipping file {file_path} due to large size ({file_size_mb:.2f}MB > 1MB)")
                    print(f"[bold yellow]Skipping file due to large size ({file_size_mb:.2f}MB)[/bold yellow]")
                    skipped_files.append(str(file_path))
                    task_logger.log_file_analysis(file_path, file_size, "skipped", "File too large")
                    continue
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    try:
                        file_content = f.read()
                        task_logger.info(f"Successfully read file content ({len(file_content)} characters)")
                    except UnicodeDecodeError:
                        log.warning(f"Skipping file {file_path} due to encoding issues")
                        print(f"[bold yellow]Skipping file due to encoding issues[/bold yellow]")
                        skipped_files.append(str(file_path))
                        task_logger.log_file_analysis(file_path, file_size, "skipped", "Encoding issues")
                        continue
                    
                log.debug(f"Sending analysis request to LLM, file size: {len(file_content)} bytes")
                task_logger.info(f"Sending analysis request to LLM")
                
                try:
                    response = llm.chat(
                        user_prompt=f"Analyze this Python file for vulnerabilities. Use ONLY these vulnerability types in your response: {valid_vuln_types}\n\n{file_content}",
                        response_model=Response
                    )
                    
                    task_logger.info(f"Received analysis response from LLM")
                    task_logger.log_file_analysis(file_path, file_size, "success")
                    
                    # Log vulnerabilities found
                    if response.vulnerability_types:
                        task_logger.log_vulnerability(file_path, response.vulnerability_types, response.confidence_score)
                    else:
                        task_logger.info(f"No vulnerabilities found in {file_path}")
                    
                    print_readable(response)
                    
                    # Store result for report
                    analyzed_files.append({
                        'file_path': str(file_path),
                        'response': response
                    })
                except Exception as api_error:
                    # Specific handling for LLM API errors
                    log.error(f"LLM API error while analyzing {file_path}: {str(api_error)}")
                    print(f"[bold red]LLM API error: {str(api_error)}[/bold red]")
                    skipped_files.append(str(file_path))
                    task_logger.log_file_analysis(file_path, file_size, "error", f"LLM API error: {str(api_error)}")
                    # Continue to next file rather than exiting
                    continue
                
            except Exception as e:
                log.error(f"Error analyzing file {file_path}: {str(e)}")
                print(f"[bold red]Error analyzing file {file_path}: {str(e)}[/bold red]")
                skipped_files.append(str(file_path))
                task_logger.log_file_analysis(file_path, file_size, "error", str(e))
                continue
        
        # Generate and save report
        if analyzed_files:
            report_path = reports_dir / generate_report_filename(repo_path)
            write_vulnerability_report(report_path, analyzed_files, skipped_files)
            task_logger.log_report_generated(report_path)
            print(f"\n[bold green]Vulnerability report saved to:[/bold green] {report_path}")
            print(f"[bold]Successfully analyzed {len(analyzed_files)} files. Skipped {len(skipped_files)} files.[/bold]")
            log.info(f"Vulnerability report saved to: {report_path}")
            
            # Log task completion
            task_logger.log_task_completed(len(analyzed_files), len(skipped_files))
        else:
            print(f"\n[bold yellow]No files were successfully analyzed. Please check logs for details.[/bold yellow]")
            log.warning("No files were successfully analyzed.")
            task_logger.log_task_failed("No files were successfully analyzed")
        
        # 通知用户克隆的仓库位置
        if cloned_dir:
            log.info(f"Cloned repository saved at: {cloned_dir}")
            task_logger.info(f"Cloned repository saved at: {cloned_dir}")
            print(f"[bold blue]Cloned repository saved at:[/bold blue] {cloned_dir}")
                
    except Exception as e:
        error_msg = f"Error during execution: {str(e)}"
        log.error(error_msg)
        print(f"[bold red]{error_msg}[/bold red]")
        
        if 'task_logger' in locals():
            task_logger.log_task_failed(error_msg)
    
    log.info(f"Task {task_id} logs saved to: {task_logs_dir}/task_{task_id}_*.log")
    return task_id

def run_web():
    """Run in web mode with FastAPI"""
    # Import inside function to avoid circular imports
    from vulnhuntr.web_api import app
    
    # Create task logs directory if it doesn't exist
    if not os.path.exists(task_logs_dir):
        os.makedirs(task_logs_dir)
        log.info(f"Created task logs directory: {task_logs_dir}")
    
    web_host = os.environ.get("VULNHUNTR_HOST", "127.0.0.1")
    web_port = int(os.environ.get("VULNHUNTR_PORT", 8000))
    
    log.info(f"Starting web server on {web_host}:{web_port}")
    uvicorn.run(app, host=web_host, port=web_port)

def cleanup_old_repos(max_repos: int = 10):
    """清理旧仓库，只保留最近的N个仓库
    
    Args:
        max_repos: 要保留的最大仓库数量
    """
    try:
        if not os.path.exists(cloned_repos_dir):
            return
            
        # 获取所有仓库目录及其创建时间
        repos = []
        for item in os.listdir(cloned_repos_dir):
            item_path = os.path.join(cloned_repos_dir, item)
            if os.path.isdir(item_path):
                stats = os.stat(item_path)
                repos.append({
                    "path": item_path,
                    "created": stats.st_ctime
                })
        
        # 按创建时间排序（最旧的在前面）
        repos.sort(key=lambda x: x["created"])
        
        # 如果仓库数量超过最大值，删除最旧的
        if len(repos) > max_repos:
            repos_to_remove = repos[:-max_repos]  # 移除最旧的仓库
            
            for repo in repos_to_remove:
                try:
                    log.info(f"正在清理旧仓库: {repo['path']}")
                    shutil.rmtree(repo["path"], ignore_errors=True)
                except Exception as e:
                    log.error(f"清理旧仓库 {repo['path']} 时出错: {str(e)}")
                    
            log.info(f"已清理 {len(repos_to_remove)} 个旧仓库")
    
    except Exception as e:
        log.error(f"清理旧仓库时出错: {str(e)}")

def run():
    """Main entry point"""
    log.info("程序启动")
    
    # 清理旧仓库
    cleanup_old_repos()
    
    parser = argparse.ArgumentParser(description="Vulnhuntr - Python code vulnerability analysis tool")
    parser.add_argument("--mode", choices=["cli", "web"], default="cli", help="Run mode: cli or web")
    parser.add_argument("--repo-path", help="Repository path to analyze (local directory or GitHub URL)")
    parser.add_argument("--analyze-path", help="Specific file or directory path to analyze")
    parser.add_argument("--llm-type", choices=["claude", "chatgpt", "ollama", "deepseek"], default="claude", help="Used LLM type")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="INFO", 
                        help="Set logging level")
    
    args = parser.parse_args()
    
    # Set log level based on command line argument
    log_level = getattr(logging, args.log_level)
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for handler in root_logger.handlers:
        handler.setLevel(log_level)
    
    log.debug(f"Command line arguments: {args}")
    log.debug(f"Log level set to {args.log_level}")
    
    if args.mode == "web":
        run_web()
    else:
        run_cli(args.repo_path, args.analyze_path, args.llm_type)

def is_github_url(url: str) -> bool:
    """Check if the provided string is a GitHub repository URL."""
    github_patterns = [
        r'https?://github\.com/[^/]+/[^/]+/?.*',
        r'git@github\.com:[^/]+/[^/]+\.git'
    ]
    return any(re.match(pattern, url) for pattern in github_patterns)

def get_repo_name_from_url(url: str) -> str:
    """Extract repository name from GitHub URL."""
    # Handle HTTPS URLs
    if url.startswith('http'):
        # Remove .git extension if present
        url = url.rstrip('/')
        if url.endswith('.git'):
            url = url[:-4]
        return url.split('/')[-1]
    # Handle SSH URLs (git@github.com:username/repo.git)
    elif url.startswith('git@'):
        repo_part = url.split(':')[-1]
        if repo_part.endswith('.git'):
            repo_part = repo_part[:-4]
        return repo_part.split('/')[-1]
    return "cloned_repo"  # Fallback name

def clone_github_repo(url: str) -> str:
    """
    Clone a GitHub repository to the cloned_repos directory.
    
    Args:
        url: GitHub repository URL
        
    Returns:
        Path to the cloned repository
    
    Raises:
        Exception: If cloning fails
    """
    repo_name = get_repo_name_from_url(url)
    # 生成唯一的仓库目录名，包含时间戳
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    repo_dir_name = f"{repo_name}_{timestamp}"
    clone_dir = str(cloned_repos_dir / repo_dir_name)
    
    try:
        log.info(f"Cloning repository from {url} to {clone_dir}")
        print(f"[bold blue]Cloning repository:[/bold blue] {url}")
        
        # 检查目录是否已存在，如果存在则先删除
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)
            log.info(f"Removed existing directory: {clone_dir}")
            
        # 运行git clone命令
        process = subprocess.run(
            ["git", "clone", url, clone_dir],
            capture_output=True,
            text=True,
            check=True
        )
        
        log.info(f"Successfully cloned repository to {clone_dir}")
        print(f"[bold green]Successfully cloned repository to:[/bold green] {clone_dir}")
        
        return clone_dir
    except subprocess.CalledProcessError as e:
        log.error(f"Failed to clone repository: {e.stderr}")
        print(f"[bold red]Failed to clone repository: {e.stderr}[/bold red]")
        # 清理目录如果克隆失败
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {e.stderr}")
    except Exception as e:
        log.error(f"Error during repository cloning: {str(e)}")
        # 清理目录如果发生错误
        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir, ignore_errors=True)
        raise

if __name__ == "__main__":
    run()
