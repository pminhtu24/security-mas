import argparse
from mas_core.graph import create_scan_graph
from mas_core.state import ScanState
from pathlib import Path
import json

def main():
    parser = argparse.ArgumentParser(
        description='Security Scanner MAS: SAST + SCA'
    )
    parser.add_argument(
        '--project',
        required=True,
        help="Path to project to scan"
    ) 
    parser.add_argument(
        '--output',
        default='results/report.json',
        help='Output report file'
    )
    args = parser.parse_args()

    print("\n" + "="*60)
    print("   SECURITY SCANNER MAS")
    print("   SAST + SCA - Parallel Execution")
    print("="*60)

    print("\n Initializing MAS...")
    app = create_scan_graph()
    initial_state: ScanState = {
        'project_path': args.project,
        'all_files': [],
        'total_files': 0,
        'sast_results': {},
        'sca_results': {},
        'final_report': {},
        'scan_status': []
    }

    print(" Starting scan...\n")
    final_state = app.invoke(initial_state)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final_state['final_report'], f, ensure_ascii=False)
    
    print("\n" + "="*60)
    print(f" Scan completed!")
    print(f" Report saved to: {output_path}")
    print("="*60 + "\n")

    summary = final_state['final_report']['summary']
    print("---> SUMMARY:")
    print(f"  Total files: {summary['total_files_scanned']}")
    print(f"  SAST issues: {summary['sast_issues']}")
    print(f"  SCA issues:  {summary['sca_issues']}")
    print(f"  TOTAL:       {summary['total_issues']} vulnerabilities")
    print()

if __name__ == '__main__':
    main()