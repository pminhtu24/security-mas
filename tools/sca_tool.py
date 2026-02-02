import subprocess
import json
import os
from typing import Dict, Any

class SnykScanner:
    def scan_dependencies(self, project_path: str):
        """
        Returns:
            {
                'tool': 'snyk',
                'vulnerabilities': [...],
                'total_issues': int,
                'error': None or Error message
            }
        """
        try:
            project_path = os.path.abspath(project_path)

            print("Snyk is scanning dependencies...")
            print(f"Project path: {project_path}")

            req_file = os.path.join(project_path, 'requirements.txt')
            if not os.path.exists(req_file):
                print(f"requirements.txt not found at: {req_file}")
                for root, dirs, files in os.walk(project_path):
                    if 'requirements.txt' in files:
                        req_file = os.path.join(root, 'requirements.txt')
                        print(f"Found requirements.txt at: {req_file}")
                        break
                else:
                    return {
                        'tool': 'snyk',
                        'vulnerabilities': [],
                        'total_issues': 0,
                        'error': 'No requirements.txt found'
                    }
            
            cmd = [
                'snyk', 'test',
                f'--file={req_file}',
                '--json',
                '--package-manager=pip'
            ]

            # Run
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=project_path
            )

            # Parse output
            if result.stdout:
                try:
                    output = json.loads(result.stdout)
                    vulnerabilities = output.get('vulnerabilities', [])
                    print(f"Snyk found {len(vulnerabilities)} issues")
                    
                    return {
                        'tool': 'snyk',
                        'vulnerabilities': vulnerabilities,
                        'total_issues': len(vulnerabilities),
                        'error': None
                    }
                except json.JSONDecodeError:
                    return {
                        'tool': 'snyk',
                        'vulnerabilities': [],
                        'total_issues': 0,
                        'error': f'Cannot parse Snyk output: {result.stdout[:200]}'
                    }
            else:
                return {
                    'tool': 'snyk',
                    'vulnerabilities': [],
                    'total_issues': 0,
                    'error': result.stderr or 'No output from Snyk'
                }
        except subprocess.TimeoutExpired:
            return {
                'tool': 'snyk',
                'vulnerabilities': [],
                'total_issues': 0,
                'error': 'Timeout after 60s'
            }
        except Exception as e:
            return {
                'tool': 'snyk',
                'vulnerabilities': [],
                'total_issues': 0,
                'error': str(e)
            }
