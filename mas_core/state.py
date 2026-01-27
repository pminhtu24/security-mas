from typing import Annotated, TypedDict, List, Dict, Any
import operator

class ScanState(TypedDict):
    project_path: str
    all_files: List[str]
    total_files: int
    #SAST output
    sast_results: Dict[str, Any]
    #SCA output
    sca_results: Dict[str, Any]
    # Final ouput
    final_report: Dict[str, Any]
    scan_status: Annotated[List[str], operator.add] # 'pending', 'scaning', 'completed'
    