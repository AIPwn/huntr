from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from pathlib import Path
import datetime
import os
import shutil
import uuid
import asyncio
from typing import List, Optional, Dict, Any

import structlog
log = structlog.get_logger()

from vulnhuntr.main import (
    initialize_llm, RepoOps, Response, VulnType, 
    reports_dir, task_logs_dir, cloned_repos_dir, generate_report_filename, 
    write_vulnerability_report, clone_github_repo, is_github_url,
    TaskLogger, cleanup_old_repos
)

# 定义分析请求模型
class AnalyzeRequest(BaseModel):
    repo_path: str
    analyze_path: Optional[str] = None
    llm_type: str = "deepseek"

# 定义任务状态枚举
class TaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

# 存储任务状态和结果的字典
tasks = {}

# 添加用于仓库删除的请求模型
class DeleteRepoRequest(BaseModel):
    repo_path: str

# 初始化 FastAPI
app = FastAPI(
    title="Vulnhuntr Web UI",
    description="Python代码漏洞分析工具",
    version="1.0.0"
)

# 挂载静态文件
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

# 配置模板
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

@app.on_event("startup")
async def startup_event():
    """启动时创建必要的目录"""
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(task_logs_dir, exist_ok=True)
    os.makedirs(cloned_repos_dir, exist_ok=True)
    
    # 检查reports目录是否可写
    if not os.access(reports_dir, os.W_OK):
        log.error(f"报告目录不可写: {reports_dir}")
    else:
        log.info(f"报告目录已确认可写: {reports_dir}")
    
    # 启动时清理旧仓库
    try:
        cleanup_old_repos(max_repos=20)  # 保留20个最近的仓库
        log.info("启动时已检查并清理旧仓库")
    except Exception as e:
        log.error(f"启动时清理旧仓库失败: {str(e)}")
        
    log.info("Web API 启动，已确保报告和任务日志目录存在")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """渲染主页"""
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )

@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest):
    """启动异步分析任务"""
    task_id = str(uuid.uuid4())[:8]
    log.info(f"接收到新的分析请求，任务ID: {task_id}")
    
    # 创建任务并设置为待处理状态
    tasks[task_id] = {
        "status": TaskStatus.PENDING,
        "progress": 0,
        "total_files": 0,
        "analyzed_files": 0,
        "skipped_files": 0,
        "message": "初始化分析任务...",
        "results": [],
        "report_path": None,
        "skipped_files_list": [],
        "start_time": datetime.datetime.now().isoformat()
    }
    
    # 在后台运行分析任务
    asyncio.create_task(run_analysis_task(task_id, request))
    
    # 返回任务标识符
    return {"task_id": task_id}

async def run_analysis_task(task_id: str, request: AnalyzeRequest):
    """在后台运行分析任务"""
    cloned_temp_dir = None
    task_logger = TaskLogger(task_id, request.repo_path, request.llm_type)
    
    try:
        # 更新任务状态为运行中
        tasks[task_id]["status"] = TaskStatus.RUNNING
        task_logger.info(f"开始分析任务: {task_id}")
        
        repo_path = request.repo_path
        
        # 如果是GitHub URL，克隆到克隆仓库目录
        if is_github_url(repo_path):
            tasks[task_id]["message"] = "正在克隆GitHub仓库..."
            task_logger.info(f"正在克隆GitHub仓库: {repo_path}")
            try:
                cloned_temp_dir = clone_github_repo(repo_path)
                repo_path = cloned_temp_dir
                task_logger.info(f"仓库已克隆到目录: {cloned_temp_dir}")
            except Exception as e:
                error_msg = f"克隆GitHub仓库失败: {str(e)}"
                log.error(error_msg)
                task_logger.error(error_msg)
                tasks[task_id]["status"] = TaskStatus.FAILED
                tasks[task_id]["message"] = error_msg
                task_logger.log_task_failed(error_msg)
                return
        
        # 初始化LLM
        tasks[task_id]["message"] = f"正在初始化{request.llm_type}模型..."
        task_logger.info(f"正在初始化LLM: {request.llm_type}")
        llm = initialize_llm(request.llm_type)
        
        # 获取漏洞类型列表
        valid_vuln_types = ", ".join([t.name for t in VulnType])
        task_logger.info(f"使用的漏洞类型: {valid_vuln_types}")
        
        # 分析文件
        repo_ops = RepoOps(repo_path)
        files_to_analyze = repo_ops.get_files_to_analyze(
            Path(request.analyze_path) if request.analyze_path else None
        )
        
        if not files_to_analyze:
            task_logger.warning(f"在目录 {repo_path} 中未找到Python文件")
            tasks[task_id]["status"] = TaskStatus.COMPLETED
            tasks[task_id]["message"] = "分析完成，未找到Python文件"
            task_logger.log_task_completed(0, 0)
            return
        
        total_files = len(files_to_analyze)
        tasks[task_id]["total_files"] = total_files
        tasks[task_id]["message"] = f"找到 {total_files} 个文件待分析..."
        task_logger.info(f"找到 {total_files} 个文件待分析")
        
        analyzed_files = []
        skipped_files = []
        
        # 基础路径，用于生成相对路径
        base_path = str(repo_path)
        task_logger.info(f"设置基础路径为: {base_path}")
        
        # 分析每个文件
        for i, file_path in enumerate(files_to_analyze):
            current_file = i + 1
            progress = int((current_file / total_files) * 100)
            
            # 获取相对路径
            abs_file_path = str(file_path)
            if abs_file_path.startswith(base_path):
                relative_path = abs_file_path[len(base_path)+1:]
            else:
                relative_path = Path(file_path).name
            
            tasks[task_id]["progress"] = progress
            tasks[task_id]["message"] = f"正在分析文件 ({current_file}/{total_files}): {relative_path}"
            task_logger.info(f"正在分析文件 ({current_file}/{total_files}): {relative_path}")
            
            try:
                # 检查文件大小
                file_size = file_path.stat().st_size
                file_size_mb = file_size / (1024 * 1024)
                task_logger.info(f"文件大小: {file_size} 字节 ({file_size_mb:.2f} MB)")
                
                # 跳过大于1MB的文件以避免超时
                if file_size_mb > 1:
                    task_logger.warning(f"由于文件过大而跳过 {relative_path} ({file_size_mb:.2f}MB > 1MB)")
                    skipped_files.append(str(file_path))
                    tasks[task_id]["skipped_files"] += 1
                    tasks[task_id]["skipped_files_list"].append(relative_path)
                    task_logger.log_file_analysis(file_path, file_size, "skipped", "文件过大")
                    continue
                
                with open(file_path, 'r', encoding='utf-8') as f:
                    try:
                        file_content = f.read()
                        task_logger.info(f"成功读取文件内容 ({len(file_content)} 字符)")
                    except UnicodeDecodeError:
                        task_logger.warning(f"由于编码问题而跳过 {relative_path}")
                        skipped_files.append(str(file_path))
                        tasks[task_id]["skipped_files"] += 1
                        tasks[task_id]["skipped_files_list"].append(relative_path)
                        task_logger.log_file_analysis(file_path, file_size, "skipped", "编码问题")
                        continue
                
                task_logger.info(f"向LLM发送分析请求")
                
                try:
                    response = llm.chat(
                        user_prompt=f"Analyze this Python file for vulnerabilities. Use ONLY these vulnerability types in your response: {valid_vuln_types}\n\n{file_content}",
                        response_model=Response
                    )
                    
                    task_logger.info(f"收到LLM分析响应")
                    task_logger.log_file_analysis(file_path, file_size, "success")
                    
                    # 记录发现的漏洞
                    if response.vulnerability_types:
                        task_logger.log_vulnerability(file_path, response.vulnerability_types, response.confidence_score)
                    else:
                        task_logger.info(f"在 {relative_path} 中未发现漏洞")
                    
                    # 添加到分析结果
                    analyzed_files.append({
                        'file_path': str(file_path),
                        'response': response
                    })
                    
                    # 更新任务状态
                    tasks[task_id]["analyzed_files"] += 1
                    
                    # 添加到API响应中，使用相对路径
                    tasks[task_id]["results"].append({
                        'file': relative_path,
                        'analysis': response.dict()
                    })
                except Exception as api_error:
                    error_msg = f"分析 {relative_path} 时LLM API错误: {str(api_error)}"
                    task_logger.error(error_msg)
                    skipped_files.append(str(file_path))
                    tasks[task_id]["skipped_files"] += 1
                    tasks[task_id]["skipped_files_list"].append(relative_path)
                    task_logger.log_file_analysis(file_path, file_size, "error", error_msg)
                    continue
            
            except Exception as e:
                error_msg = f"分析文件 {relative_path} 时出错: {str(e)}"
                task_logger.error(error_msg)
                skipped_files.append(str(file_path))
                tasks[task_id]["skipped_files"] += 1
                tasks[task_id]["skipped_files_list"].append(relative_path)
                task_logger.log_file_analysis(file_path, file_size, "error", str(e))
                continue
        
        # 生成报告
        report_path = None
        if analyzed_files:
            try:
                # 确保报告目录存在
                if not os.path.exists(reports_dir):
                    os.makedirs(reports_dir)
                    log.info(f"创建报告目录: {reports_dir}")
                
                report_filename = generate_report_filename(repo_path)
                report_path = reports_dir / report_filename
                
                task_logger.info(f"正在生成漏洞报告: {report_path}")
                tasks[task_id]["message"] = "正在生成漏洞报告..."
                
                # 写入报告文件
                write_vulnerability_report(report_path, analyzed_files, skipped_files)
                
                # 验证报告是否成功创建
                if os.path.exists(report_path):
                    task_logger.log_report_generated(report_path)
                    tasks[task_id]["report_path"] = str(report_path)
                    log.info(f"漏洞报告已保存到: {report_path}")
                    task_logger.info(f"漏洞报告已保存到: {report_path}")
                else:
                    error_msg = f"无法创建报告文件: {report_path}"
                    log.error(error_msg)
                    task_logger.error(error_msg)
            except Exception as e:
                error_msg = f"生成报告时出错: {str(e)}"
                log.error(error_msg)
                task_logger.error(error_msg)
                # 继续执行，不要因为报告生成失败而使整个任务失败
        
        # 更新任务状态为已完成
        tasks[task_id]["status"] = TaskStatus.COMPLETED
        tasks[task_id]["progress"] = 100
        tasks[task_id]["message"] = f"分析完成！已分析 {len(analyzed_files)} 个文件，跳过 {len(skipped_files)} 个文件"
        tasks[task_id]["end_time"] = datetime.datetime.now().isoformat()
        task_logger.log_task_completed(len(analyzed_files), len(skipped_files))
    
    except Exception as e:
        error_msg = f"执行过程中出错: {str(e)}"
        log.error(error_msg)
        task_logger.error(error_msg)
        tasks[task_id]["status"] = TaskStatus.FAILED
        tasks[task_id]["message"] = error_msg
        tasks[task_id]["end_time"] = datetime.datetime.now().isoformat()
        task_logger.log_task_failed(error_msg)
    
    finally:
        # 显示克隆的仓库相对路径
        if cloned_temp_dir:
            repo_relative_path = cloned_temp_dir.replace(str(cloned_repos_dir) + os.path.sep, "")
            task_logger.info(f"仓库保存在目录: {repo_relative_path}")
            tasks[task_id]["cloned_repo_path"] = repo_relative_path

@app.get("/api/tasks/{task_id}")
async def get_task_status(task_id: str):
    """获取任务状态"""
    if task_id not in tasks:
        raise HTTPException(status_code=404, detail="任务未找到")
    
    return tasks[task_id]

@app.get("/api/reports", response_class=JSONResponse)
async def list_reports():
    """列出所有可用的报告"""
    try:
        report_files = list(reports_dir.glob("*.txt"))
        reports = []
        
        for report_file in report_files:
            # 获取文件统计数据
            stats = report_file.stat()
            reports.append({
                "filename": report_file.name,
                "path": str(report_file),
                "size_bytes": stats.st_size,
                "created": datetime.datetime.fromtimestamp(stats.st_ctime).isoformat()
            })
            
        return {"reports": sorted(reports, key=lambda x: x["created"], reverse=True)}
    except Exception as e:
        log.error(f"列出报告时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/{filename}", response_class=HTMLResponse)
async def get_report(filename: str):
    """通过文件名获取特定报告"""
    try:
        report_path = reports_dir / filename
        if not report_path.exists() or not report_path.is_file():
            raise HTTPException(status_code=404, detail="报告未找到")
            
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # 将纯文本转换为HTML
        html_content = content.replace("\n", "<br>").replace(" ", "&nbsp;")
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>漏洞报告</title>
            <style>
                body {{ font-family: monospace; padding: 20px; }}
                .report {{ white-space: pre-wrap; }}
            </style>
        </head>
        <body>
            <h1>漏洞报告: {filename}</h1>
            <div class="report">
                {html_content}
            </div>
        </body>
        </html>
        """
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取报告时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tasks/{task_id}/logs", response_class=JSONResponse)
async def get_task_logs(task_id: str):
    """获取任务的日志"""
    try:
        # 查找与任务ID匹配的日志文件
        log_files = list(Path(task_logs_dir).glob(f"task_{task_id}_*.log"))
        
        if not log_files:
            raise HTTPException(status_code=404, detail="未找到任务日志")
        
        # 读取最新的日志文件
        log_file = sorted(log_files, key=lambda x: x.stat().st_mtime, reverse=True)[0]
        
        with open(log_file, 'r', encoding='utf-8') as f:
            log_lines = f.readlines()
        
        # 解析日志行
        logs = []
        for line in log_lines:
            try:
                logs.append(line.strip())
            except:
                logs.append(line.strip())
        
        return {"logs": logs, "log_file": str(log_file)}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"获取任务日志时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/repos")
async def list_repos():
    """列出所有已克隆的仓库"""
    try:
        if not os.path.exists(cloned_repos_dir):
            return {"repos": []}
        
        repos = []
        for item in os.scandir(cloned_repos_dir):
            if item.is_dir():
                # 只显示相对路径（仓库名）而非完整路径
                repo_name = os.path.basename(item.path)
                repos.append({
                    "name": repo_name,
                    "path": repo_name,  # 只返回相对路径
                    "created": datetime.datetime.fromtimestamp(item.stat().st_ctime).isoformat()
                })
        
        # 按创建时间倒序排序
        repos.sort(key=lambda x: x["created"], reverse=True)
        return {"repos": repos}
    except Exception as e:
        log.error(f"获取仓库列表时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=f"获取仓库列表时出错: {str(e)}")

@app.delete("/api/repos/{repo_name}")
async def delete_repo(repo_name: str):
    """删除指定的已克隆仓库"""
    try:
        # 安全检查：确保repo_name不包含任何路径注入的尝试
        if "/" in repo_name or "\\" in repo_name or ".." in repo_name:
            raise HTTPException(status_code=400, detail="无效的仓库名")
        
        repo_path = os.path.join(cloned_repos_dir, repo_name)
        
        if not os.path.exists(repo_path):
            raise HTTPException(status_code=404, detail=f"仓库 '{repo_name}' 不存在")
        
        # 删除仓库目录
        shutil.rmtree(repo_path)
        log.info(f"已删除仓库: {repo_name}")
        
        return {"status": "success", "message": f"已删除仓库 '{repo_name}'"}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"删除仓库时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=f"删除仓库时出错: {str(e)}")

@app.post("/api/cloned_repos/cleanup", response_class=JSONResponse)
async def clean_old_repositories(max_repos: int = 10):
    """手动清理旧仓库"""
    try:
        # 获取清理前的仓库数量
        repo_count_before = len([item for item in os.listdir(cloned_repos_dir) 
                               if os.path.isdir(os.path.join(cloned_repos_dir, item))])
        
        # 执行清理
        cleanup_old_repos(max_repos=max_repos)
        
        # 获取清理后的仓库数量
        repo_count_after = len([item for item in os.listdir(cloned_repos_dir) 
                              if os.path.isdir(os.path.join(cloned_repos_dir, item))])
        
        removed_count = repo_count_before - repo_count_after
        
        return {
            "success": True, 
            "message": f"已清理 {removed_count} 个旧仓库",
            "repo_count_before": repo_count_before,
            "repo_count_after": repo_count_after,
            "removed_count": removed_count
        }
    except Exception as e:
        log.error(f"手动清理旧仓库时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 