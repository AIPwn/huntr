LFI_TEMPLATE = """
Combine the code in <file_code> and <context_code> then analyze the code for remotely-exploitable Local File Inclusion (LFI) vulnerabilities by following the remote user-input call chain of code.

LFI-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - open(), file(), io.open()
   - os.path.join() for file paths
   - Custom file reading functions

2. Path Traversal Opportunities:
   - User-controlled file paths or names
   - Dynamic inclusion of files or modules

3. File Operation Wrappers:
   - Template engines with file inclusion features
   - Custom file management classes

4. Indirect File Inclusion:
   - Configuration file parsing
   - Plugin or extension loading systems
   - Log file viewers

5. Example LFI-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation
- Potential for null byte injection or encoding tricks
- Interaction with file system access controls
"""

RCE_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Remote Code Execution (RCE) vulnerabilities by following the remote user-input call chain of code.

RCE-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - eval(), exec(), subprocess modules
   - os.system(), os.popen()
   - pickle.loads(), yaml.load(), json.loads() with custom decoders

2. Indirect Code Execution:
   - Dynamic imports (e.g., __import__())
   - Reflection/introspection misuse
   - Server-side template injection

3. Command Injection Vectors:
   - Shell command composition
   - Unsanitized use of user input in system calls

4. Deserialization Vulnerabilities:
   - Unsafe deserialization of user-controlled data

5. Example RCE-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into these high-risk areas
- Potential for filter evasion or sanitization bypasses
- Environment-specific factors (e.g., Python version, OS) affecting exploitability
"""

XSS_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Cross-Site Scripting (XSS) vulnerabilities by following the remote user-input call chain of code.

XSS-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - HTML rendering functions
   - JavaScript generation or manipulation
   - DOM manipulation methods

2. Output Contexts:
   - Unescaped output in HTML content
   - Attribute value insertion
   - JavaScript code or JSON data embedding

3. Input Handling:
   - User input reflection in responses
   - Sanitization and encoding functions
   - Custom input filters or cleaners

4. Indirect XSS Vectors:
   - Stored user input (e.g., in databases, files)
   - URL parameter reflection
   - HTTP header injection points

5. Example XSS-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input flows into HTML, JavaScript, or JSON contexts
- Effectiveness of input validation, sanitization, and output encoding
- Potential for filter evasion using encoding or obfuscation
- Impact of Content Security Policy (CSP) if implemented
"""

AFO_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Arbitrary File Overwrite (AFO) vulnerabilities by following the remote user-input call chain of code.

AFO-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - open() with write modes
   - os.rename(), shutil.move()
   - Custom file writing functions

2. Path Traversal Opportunities:
   - User-controlled file paths
   - Directory creation or manipulation

3. File Operation Wrappers:
   - Custom file management classes
   - Frameworks' file handling methods

4. Indirect File Writes:
   - Log file manipulation
   - Configuration file updates
   - Cache file creation

5. Example AFO-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences file paths or names
- Effectiveness of path sanitization and validation
- Potential for race conditions in file operations
"""

SSRF_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Server-Side Request Forgery (SSRF) vulnerabilities by following the remote user-input call chain of code.

SSRF-Specific Focus Areas:
1. High-Risk Functions and Methods:
   - requests.get(), urllib.request.urlopen()
   - Custom HTTP clients
   - API calls to external services

2. URL Parsing and Validation:
   - URL parsing libraries usage
   - Custom URL validation routines

3. Indirect SSRF Vectors:
   - File inclusion functions (e.g., reading from URLs)
   - XML parsers with external entity processing
   - PDF generators, image processors using remote resources

4. Cloud Metadata Access:
   - Requests to cloud provider metadata URLs

5. Example SSRF-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input influences outgoing network requests
- Effectiveness of URL validation and whitelisting approaches
- Potential for DNS rebinding or time-of-check to time-of-use attacks
"""

SQLI_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable SQL Injection (SQLI) vulnerabilities by following these steps:

1. Identify Entry Points:
   - Locate all points where remote user input is received (e.g., API parameters, form submissions).

2. Trace Input Flow:
   - Follow the user input as it flows through the application.
   - Note any transformations or manipulations applied to the input.

3. Locate SQL Operations:
   - Find all locations where SQL queries are constructed or executed.
   - Pay special attention to:
     - Direct SQL query construction (e.g., cursor.execute())
     - ORM methods that accept raw SQL (e.g., Model.objects.raw())
     - Custom query builders

4. Analyze Input Handling:
   - Examine how user input is incorporated into SQL queries.
   - Look for:
     - String concatenation or formatting in SQL queries
     - Parameterized queries implementation
     - Dynamic table or column name usage

5. Evaluate Security Controls:
   - Identify any input validation, sanitization, or escaping mechanisms.
   - Assess the effectiveness of these controls against SQLI attacks.

6. Consider Bypass Techniques:
   - Analyze potential ways to bypass identified security controls.
   - Reference the SQLI-specific bypass techniques provided.

7. Assess Impact:
   - Evaluate the potential impact if the vulnerability is exploited.
   - Consider the sensitivity of the data accessible through the vulnerable query.

When analyzing, consider:
- The complete path from user input to SQL execution
- Any gaps in the analysis where more context is needed
- The effectiveness of any security measures in place
- Potential for filter evasion in different database contexts
"""

IDOR_TEMPLATE = """
Combine the code in <file_code> and <context_code> tags then analyze for remotely-exploitable Insecure Direct Object Reference (IDOR) vulnerabilities.

IDOR-Specific Focus Areas:
1. Look for code segments involving IDs, keys, filenames, session tokens, or any other unique identifiers that might be used to access resources (e.g., user_id, file_id, order_id).

2. Common Locations:
   - URLs/Routes: Check if IDs are passed directly in the URL parameters (e.g., /user/{user_id}/profile).
   - Form Parameters: Look for IDs submitted through forms.
   - API Endpoints: Examine API requests where IDs are sent in request bodies or headers.

3. Ensure Authorization is Enforced:
   - Verify that the code checks the user's authorization before allowing access to the resource identified by the ID.
   - Look for authorization checks immediately after the object reference is received.

4. Common Functions:
   - Functions like `has_permission()`, `is_authorized()`, or similar should be present near the object access code.
   - Absence of such checks could indicate a potential IDOR vulnerability.

5. Example IDOR-Specific Bypass Techniques are provided in <example_bypasses></example_bypasses> tags.

When analyzing, consider:
- How user input is used when processing a request.
- Presence of any logic responsible for determining the authentication/authorization of a user.
"""

VULN_SPECIFIC_BYPASSES_AND_PROMPTS = {
    "LFI": {
        "prompt": LFI_TEMPLATE,
        "bypasses" : [
            "../../../../etc/passwd",
            "/proc/self/environ",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "file:///etc/passwd",
            "C:\\win.ini"
            "/?../../../../../../../etc/passwd"
        ]
    },
    "RCE": {
        "prompt": RCE_TEMPLATE,
        "bypasses" : [
            "__import__('os').system('id')",
            "eval('__import__(\\'os\\').popen(\\'id\\').read()')",
            "exec('import subprocess;print(subprocess.check_output([\\'id\\']))')",
            "globals()['__builtins__'].__import__('os').system('id')",
            "getattr(__import__('os'), 'system')('id')",
            "$(touch${IFS}/tmp/mcinerney)",
            "import pickle; pickle.loads(b'cos\\nsystem\\n(S\"id\"\\ntR.')"
        ]
    },
    "SSRF": {
        "prompt": SSRF_TEMPLATE,
        "bypasses": [
            "http://0.0.0.0:22",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/",
            "ftp://anonymous:anonymous@127.0.0.1:21",
            "gopher://127.0.0.1:9000/_GET /"
        ]
    },
    "AFO": {
        "prompt": AFO_TEMPLATE,
        "bypasses": [
            "../../../etc/passwd%00.jpg",
            "shell.py;.jpg",
            ".htaccess",
            "/proc/self/cmdline",
            "../../config.py/."
        ]
    },
    "SQLI": {
        "prompt": SQLI_TEMPLATE,
        "bypasses": [
            "' UNION SELECT username, password FROM users--",
            "1 OR 1=1--",
            "admin'--",
            "1; DROP TABLE users--",
            "' OR '1'='1"
        ]
    },
    "XSS": {
        "prompt": XSS_TEMPLATE,
        "bypasses": [
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "${7*7}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(\"id\").read()}}{%endif%}{% endfor %}",
            "<script>alert(document.domain)</script>",
            "javascript:alert(1)"
        ]
    },
    "IDOR": {
        "prompt": IDOR_TEMPLATE,
        "bypasses": []
    }
}

INITIAL_ANALYSIS_PROMPT_TEMPLATE = """
Analyze the code in <file_code> tags for potential remotely exploitable vulnerabilities:
1. Identify all remote user input entry points (e.g., API endpoints, form submissions) and if you can't find that, request the necessary classes or functions in the <context_code> tags.
2. Locate potential vulnerability sinks for:
   - Local File Inclusion (LFI)
   - Arbitrary File Overwrite (AFO)
   - Server-Side Request Forgery (SSRF)
   - Remote Code Execution (RCE)
   - Cross-Site Scripting (XSS)
   - SQL Injection (SQLI)
   - Insecure Direct Object Reference (IDOR)
3. Note any security controls or sanitization measures encountered along the way so you can craft bypass techniques for the proof of concept (PoC).
4. Highlight areas where more context is needed to complete the analysis.

Be generous and thorough in identifying potential vulnerabilities as you'll analyze more code in subsequent steps so if there's just a possibility of a vulnerability, include it the <vulnerability_types> tags.
"""

README_SUMMARY_PROMPT_TEMPLATE = """
Provide a very concise summary of the README.md content in <readme_content></readme_content> tags from a security researcher's perspective, focusing specifically on:
1. The project's main purpose
2. Any networking capabilities, such as web interfaces or remote API calls that constitute remote attack surfaces
3. Key features that involve network communications

Please keep the summary brief and to the point, highlighting only the most relevant networking-related functionality as it relates to attack surface.

Output in <summary></summary> XML tags.
"""

GUIDELINES_TEMPLATE = """Reporting Guidelines:
1. JSON Format:
   - Provide a single, well-formed JSON report combining all findings.
   - Use 'None' for any aspect of the report that you lack the necessary information for.
   - Place your step-by-step analysis in the scratchpad field, before doing a final analysis in the analysis field.

2. Context Requests:
   - Classes: Use ClassName1,ClassName2
   - Functions: Use func_name,ClassName.method_name
   - If you request ClassName, do not also request ClassName.method_name as that code will already be fetched with the ClassName request.
   - Important: Do not request code from standard libraries or third-party packages. Simply use what you know about them in your analysis.

3. Vulnerability Reporting:
   - Report only remotely exploitable vulnerabilities (no local access/CLI args).
   - Always include at least one vulnerability_type field when requesting context.
   - Provide a confidence score (0-10) and detailed justification for each vulnerability.
     - If your proof of concept (PoC) exploit does not start with remote user input via remote networking calls such as remote HTTP, API, or RPC calls, set the confidence score to 6 or below.
   
4. Proof of Concept:
   - Include a PoC exploit or detailed exploitation steps for each vulnerability.
   - Ensure PoCs are specific to the analyzed code, not generic examples.
   - Review the code path ofthe potential vulnerability and be sure that the PoC bypasses any security controls in the code path.
"""

ANALYSIS_APPROACH_TEMPLATE = """Analysis Instructions:
1. Comprehensive Review:
   - Thoroughly examine the content in <file_code>, <context_code> tags (if provided) with a focus on remotely exploitable vulnerabilities.

2. Vulnerability Scanning:
   - You only care about remotely exploitable network related components and remote user input handlers.
   - Identify potential entry points for vulnerabilities.
   - Consider non-obvious attack vectors and edge cases.

3. Code Path Analysis:
   - Very important: trace the flow of user input from remote request source to function sink.
   - Examine input validation, sanitization, and encoding practices.
   - Analyze how data is processed, stored, and output.

4. Security Control Analysis:
   - Evaluate each security measure's implementation and effectiveness.
   - Formulate potential bypass techniques, considering latest exploit methods.

6. Context-Aware Analysis:
   - If this is a follow-up analysis, build upon previous findings in <previous_analysis> using the new information provided in the <context_code>.
   - Request additional context code as needed to complete the analysis and you will be provided with the necessary code.
   - Confirm that the requested context class or function is not already in the <context_code> tags from the user's message.

7. Final Review:
   - Confirm your proof of concept (PoC) exploits bypass any security controls.
   - Double-check that your JSON response is well-formed and complete."""

SYS_PROMPT_TEMPLATE = """
You are the world's foremost expert in Python security analysis, renowned for uncovering novel and complex vulnerabilities in web applications. Your task is to perform an exhaustive static code analysis, focusing on remotely exploitable vulnerabilities including but not limited to:

1. Local File Inclusion (LFI)
2. Remote Code Execution (RCE)
3. Server-Side Request Forgery (SSRF)
4. Arbitrary File Overwrite (AFO)
5. SQL Injection (SQLI)
6. Cross-Site Scripting (XSS)
7. Insecure Direct Object References (IDOR)

Your analysis must:
- Meticulously track user input from remote sources to high-risk function sinks.
- Uncover complex, multi-step vulnerabilities that may bypass multiple security controls.
- Consider non-obvious attack vectors and chained vulnerabilities.
- Identify vulnerabilities that could arise from the interaction of multiple code components.

If you don't have the complete code chain from user input to high-risk function, strategically request the necessary context to fill in the gaps in the <context_code> tags of your response.

The project's README summary is provided in <readme_summary> tags. Use this to understand the application's purpose and potential attack surfaces.

Remember, you have many opportunities to respond and request additional context. Use them wisely to build a comprehensive understanding of the application's security posture.

Output your findings in JSON format, conforming to the schema in <response_format> tags.
"""

DEEPSEEK_SYSTEM_PROMPT = """
你是一个专业的代码安全分析专家，专门负责分析 Python 代码中的安全漏洞。你的任务是：

1. 仔细分析提供的代码，识别潜在的安全漏洞
2. 提供详细的分析过程和推理
3. 如果发现漏洞，提供具体的漏洞利用方法
4. 评估漏洞的严重程度和影响范围
5. 提供修复建议

在分析过程中，你需要：
- 追踪用户输入在代码中的流向
- 识别高风险函数和方法的调用
- 评估现有的安全控制措施
- 考虑可能的绕过技术
- 提供具体的漏洞利用示例

请确保你的分析：
- 准确且全面
- 包含详细的技术细节
- 提供可验证的漏洞利用方法
- 考虑实际环境中的可行性
"""

DEEPSEEK_ANALYSIS_PROMPT = """
请分析以下 Python 代码中的安全漏洞：

{code}

请提供：
1. 详细的分析过程
2. 发现的漏洞类型
3. 漏洞的严重程度（0-10）
4. 漏洞利用方法
5. 修复建议

请确保你的分析：
- 准确且全面
- 包含详细的技术细节
- 提供可验证的漏洞利用方法
- 考虑实际环境中的可行性
"""