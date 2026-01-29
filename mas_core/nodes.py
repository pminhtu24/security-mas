import os
from .state import ScanState
from tools.sast_tool import SemgrepScanner
from tools.sca_tool import SnykScanner
from .schemas.llm_analyzer import analyze_with_llm
from typing import List, Dict, Any


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
        total_files=state['total_files'],
        project_path=state['project_path']
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
