import subprocess 
import json
from typing import Dict, List, Any

class SemgrepScanner:
    def __init__(self, rules_config: str="auto"):
        """
        Args:
            rules_config: 'auto' or custom rules path
        """
        self.rules_config = rules_config

    def scan_files(self, file_paths: List[str]) -> Dict[str, Any]:
        """
        Returns:
            {
                'tool': 'semgrep',
                'total_files': int,
                'vulnerabilities': [...]
                'total_issues': int,
                'error': None or Error message
            }
        """
        if not file_paths:
            return {
                'tool': 'semgrep',
                'total_files': 0,
                'vulnerabilities': [],
                'total_issues': 0,
                'error': None
            }
        
        try:
            print(f"Semgrep is scanning {len(file_paths)} files...")
            cmd = [
                'semgrep',
                '--config', self.rules_config,
                '--json',
                '--quiet'
            ] + file_paths

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode==0 or result.returncode==1:
                output = json.loads(result.stdout)
                vulnerabilities = output.get('results', [])
                print(f"Semgrep found {len(vulnerabilities)} issues")
                return {
                    'tool': 'semgrep',
                    'total_files': len(file_paths),
                    'vulnerabilities': vulnerabilities,
                    'total_issues': len(vulnerabilities),
                    'error': None
                }
            else:
                return {
                    'tool': 'semgrep',
                    'total_files': len(file_paths),
                    'vulnerabilities': [],
                    'total_issues': 0,
                    'error': result.stderr
                }
        except subprocess.TimeoutExpired:
            return {
                'tool': 'semgrep',
                'total_files': len(file_paths),
                'vulnerability': [],
                'total_issues': 0,
                'error': 'Timeout after 60s'
            }
        except Exception as e:
            return {
                'tool': 'semgrep',
                'total_files': len(file_paths),
                'vulnerability': [],
                'total_issues': 0,
                'error': str(e)
            }
