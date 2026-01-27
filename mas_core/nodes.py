import os
from .state import ScanState
from tools.sast_tool import SemgrepScanner
from tools.sca_tool import SnykScanner
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
    print("AGGREGATOR: Aggregates results...")
    print("="*60)

    sast_results = state.get('sast_results', {})
    sca_results = state.get('sca_results', {})

    total_sast_issues = sast_results.get('total_issues', 0)
    total_sca_issues = sca_results.get('total_issues', 0)

    final_report = {
        'summary': {
            'total_files_scanned': state['total_files'],
            'sast_issues': total_sast_issues,
            'sca_issues': total_sca_issues,
            'total_issues': total_sast_issues + total_sca_issues
        },
        'sast_details': sast_results,
        'sca_details': sca_results
    }
    print(f"\n SUMMARY OF RESULTS:")
    print(f"   Files scanned: {state['total_files']}")
    print(f"   SAST issues: {total_sast_issues}")
    print(f"   SCA issues: {total_sca_issues}")
    print(f"   TOTAL: {total_sast_issues + total_sca_issues} vulnerabilities")
    return {
        'final_report': final_report,
        'scan_status': ['completed']
    }