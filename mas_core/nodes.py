import os

from pydantic import SecretStr
from .state import ScanState
from tools.sast_tool import SemgrepScanner
from tools.sca_tool import SnykScanner
from dotenv import load_dotenv
load_dotenv()
from langchain_openai import ChatOpenAI
from .schemas.security import (
    SecurityIssue,
    LLMAnalysisResult
)
from typing import List, Dict, Any
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


#========================= Node 1: COORDINATOR ===========================
def coordinator_node(state: ScanState) -> Dict[str, Any]:
    """
    Node analyze project, finding files to scan
    """
    print("\n" + "="*60)
    print("COORDINATOR: Analyze project...")
    print("\n" + "="*60)

    project_path = state['project_path']
    all_files = scan_project_files(project_path)
    print(f" ---> Found {len(all_files)} files to scan")
    for f in all_files[:5]: 
        print(f"  - {f}")
    if len(all_files) > 5:
        print(f"  ... and {len(all_files) - 5} other files")
    
    return {
        'all_files': all_files,
        'total_files': len(all_files),
        'scan_status': ['ready_to_scan']
    }

def scan_project_files(project_path: str) -> List[str]:
    file_extensions = {'.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.go', '.rb'}
    ignore_dirs = {'node_modules', '.git', 'venv', '.venv', '__pycache__', 'build', 'dist'}
    
    files = []
    for root, dirs, filenames in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]

        for filename in filenames:
            if any(filename.endswith(ext) for ext in file_extensions):
                file_path = os.path.join(root, filename)
                files.append(file_path)
    return files

#======================== Node 2: SAST Worker ==============================
def sast_worker_node(state: ScanState) -> Dict[str, Any]:
    """
    Node scan code with Semgrep
    Parallel with SCA worker
    """

    print("\n" + "="*60)
    print("SAST WORKER: Scanning code...")
    print("="*60)

    scanner = SemgrepScanner(rules_config='auto')
    results = scanner.scan_files(state['all_files'])
    
    return {
        'sast_results': results,
        'scan_status': ['sast_completed']
    } 

# ======================= Node 3: SCA worker ================================
def sca_worker_node(state: ScanState) -> Dict[str, Any]:    
    """
    Node scan dependencies with Snyk
    Parallel with SAST worker
    """
    print("\n" + "="*60)
    print("SCA WORKER: Scanning code...")
    print("="*60)

    scanner = SnykScanner()
    results = scanner.scan_dependencies(state['project_path'])
    return {
        'sca_results': results,
        'scan_status': ['sca_completed']
    }

# ====================== Node 4: AGGREGATOR =================================
def aggregator_node(state: ScanState) -> Dict[str, Any]:
    """ 
    Node aggregates results from SAST and SCA
    """
    print("\n" + "="*60)
    print("AGGREGATOR: AI Security Analysis...")
    print("="*60)

    sast_results = state.get('sast_results', {})
    sca_results = state.get('sca_results', {})

    total_sast_issues = sast_results.get('total_issues', 0)
    total_sca_issues = sca_results.get('total_issues', 0)

    llm_analysis = analyze_with_llm(
        sast_results=sast_results,
        sca_results=sca_results,
        total_files=state['total_files']
    )

    final_report = {
        "summary": {
            "total_files_scanned": state["total_files"],
            "sast_issues": total_sast_issues,
            "sca_issues": total_sca_issues,
            "total_issues": (total_sast_issues + total_sca_issues),
            "overall_risk": llm_analysis.overall_risk # type: ignore
        },
        "issues": [issue.model_dump() for issue in llm_analysis.issues], # type: ignore
        "remediation_priority": llm_analysis.remediation_priority # type: ignore
    }

    return {
        "final_report": final_report,
        "scan_status": ["completed"]
    }


def analyze_with_llm(sast_results: Dict, sca_results: Dict, total_files: int): 
    llm = ChatOpenAI( 
        model = "gpt-5.2",
        temperature=0.1,
        api_key= SecretStr(OPENAI_API_KEY) if OPENAI_API_KEY else None

    ).with_structured_output(LLMAnalysisResult)
    # Extract vulnerabilities (limit to avoid token overflow)
    sast_vulns = sast_results.get('vulnerabilities', [])[:20]
    sca_vulns = sca_results.get('vulnerabilities', [])[:20]

    sast_summary = format_sast_findings(sast_vulns, project_path)
    sca_summary = format_sca_findings(sca_vulns, project_path)

    # Construct detailed prompt
    prompt = f"""You are a senior Application Security Engineer analyzing security scan results.

📋 SCAN CONTEXT:
- Total files scanned: {total_files}
- SAST findings: {len(sast_vulns)} issues detected
- SCA findings: {len(sca_vulns)} issues detected

🔍 SAST FINDINGS (Semgrep):
{sast_summary}

📦 SCA FINDINGS (Snyk):
{sca_summary}

🎯 YOUR TASK:
1. Convert raw findings into structured SecurityIssue objects
2. Deduplicate similar issues across tools
3. Fill in code locations (file_path, line numbers) when available
4. Provide actionable fix suggestions
5. Determine overall project risk level (Critical/High/Medium/Low)
6. Prioritize remediation steps

⚠️ IMPORTANT RULES:
- Only include line numbers if they exist in the raw data
- For fix suggestions, provide concrete code patches when possible
- Prioritize by: exploitability > impact > ease of fix
- Overall risk should reflect the most severe issue found
- Remediation priority should list 3-5 actionable steps

Return structured analysis following the LLMAnalysisResult schema.
"""
    try:
        analysis = llm.invoke(prompt)
        
        print(f"\n✅ LLM Analysis completed:")
        print(f"   - Unified {len(analysis.issues)} security issues") # type: ignore
        print(f"   - Overall risk: {analysis.overall_risk}")    # type: ignore
        print(f"   - {len(analysis.remediation_priority)} priority actions") # type: ignore
        
        return analysis # type: ignore
        
    except Exception as e:
        print(f"\n❌ LLM Analysis failed: {e}")
        
def format_sast_findings(vulnerabilities: List[Dict]) -> str:
    if not vulnerabilities:
        return "No SAST issues found."
    
    formatted = []
    for idx, vuln in enumerate(vulnerabilities, 1):
        entry = f"{idx}. {vuln.get('check_id', 'Unknown')}"
        entry += f"\n   Severity: {vuln.get('severity', 'N/A')}"
        entry += f"\n   Message: {vuln.get('message', 'N/A')}"
        
        if 'path' in vuln:
            entry += f"\n   File: {vuln['path']}"
        if 'line' in vuln:
            entry += f"\n   Line: {vuln['line']}"
            
        formatted.append(entry)
    
    return "\n\n".join(formatted)


def format_sca_findings(vulnerabilities: List[Dict]) -> str:
    if not vulnerabilities:
        return "No SCA issues found."
    
    formatted = []
    for idx, vuln in enumerate(vulnerabilities, 1):
        entry = f"{idx}. {vuln.get('title', 'Unknown vulnerability')}"
        entry += f"\n   Severity: {vuln.get('severity', 'N/A')}"
        entry += f"\n   Package: {vuln.get('package', 'N/A')}"
        entry += f"\n   Version: {vuln.get('version', 'N/A')}"
        
        if 'fixed_in' in vuln:
            entry += f"\n   Fix: Upgrade to {vuln['fixed_in']}"
            
        formatted.append(entry)
    
    return "\n\n".join(formatted)


    