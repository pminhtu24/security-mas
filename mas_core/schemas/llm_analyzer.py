import os
from typing import Dict, List
from pydantic import SecretStr
from langchain_openai import ChatOpenAI
from .security import LLMAnalysisResult


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
def analyze_with_llm(sast_results: Dict, sca_results: Dict, total_files: int,  project_path: str): 
    
    llm = ChatOpenAI( 
        model = "gpt-5.2",
        temperature=0.1,
        api_key= SecretStr(OPENAI_API_KEY) if OPENAI_API_KEY else None

    ).with_structured_output(LLMAnalysisResult)
    sast_vulns = sast_results.get('vulnerabilities', [])[:15] 
    sca_vulns = sca_results.get('vulnerabilities', [])[:15]

    # Enhanced formatting with code snippets
    sast_summary = format_sast_findings_with_code(sast_vulns, project_path)
    sca_summary = format_sca_findings(sca_vulns)

    prompt = f"""You are a senior Application Security Engineer. Your job is to provide ACTIONABLE, DETAILED security fixes.

📋 SCAN CONTEXT:
- Total files scanned: {total_files}
- SAST findings: {len(sast_vulns)} code vulnerabilities
- SCA findings: {len(sca_vulns)} dependency issues

🔍 SAST FINDINGS (with code context):
{sast_summary}

📦 SCA FINDINGS:
{sca_summary}

🎯 YOUR MISSION:
For EACH finding, you must:

1. **Extract exact location**: Use file_path and line numbers FROM THE RAW DATA ABOVE
2. **Write detailed fix description**: Explain WHAT to change and WHY
3. **Generate unified diff patch** when possible, following this format:

PATCH FORMAT EXAMPLE:
```diff
--- a/app.py
+++ b/app.py
@@ -10,7 +10,8 @@
 def get_user(user_id):
-    query = f"SELECT * FROM users WHERE id = {{user_id}}"
-    return db.execute(query)
+    # Fixed: Use parameterized query to prevent SQL injection
+    query = "SELECT * FROM users WHERE id = ?"
+    return db.execute(query, [user_id])
```

⚠️ CRITICAL RULES:
- Line numbers MUST match the data above (don't invent them!)
- If no line number in raw data, set start_line to 0
- Patches should be REAL, executable diffs (not pseudocode)
- For dependency issues: specify exact upgrade command
- Prioritize fixes by: CRITICAL > HIGH > exploitability > impact
- Generate 3-5 remediation steps in order of urgency

EXAMPLES OF GOOD FIXES:

**SQL Injection Fix:**
```
description: "Replace string formatting with parameterized queries"
patch: "--- a/app.py\\n+++ b/app.py\\n@@ -5,2 +5,3 @@\\n-query = f\\"SELECT * FROM users WHERE id={{uid}}\\"\\n+query = \\"SELECT * FROM users WHERE id=?\\"\\n+cursor.execute(query, [uid])"
```

**XSS Fix:**
```
description: "Use auto-escaping template instead of raw HTML concatenation"
patch: "--- a/views.py\\n+++ b/views.py\\n@@ -10,2 +10,3 @@\\n-return f'<div>{{user_input}}</div>'\\n+from markupsafe import escape\\n+return f'<div>{{escape(user_input)}}</div>'"
```

**Dependency Fix:**
```
description: "Upgrade vulnerable package to patched version"
patch: null
(For SCA, patch is typically null, but description should include exact command like: "Run: pip install requests==2.31.0")
```

NOW ANALYZE THE FINDINGS ABOVE AND RETURN STRUCTURED SecurityIssue OBJECTS WITH REAL, ACTIONABLE FIXES.
"""

    try:
        analysis = llm.invoke(prompt)
        
        print(f"\n✅ LLM Analysis completed:")
        print(f"   - Unified {len(analysis.issues)} security issues") # type: ignore
        print(f"   - Overall risk: {analysis.overall_risk}")    # type: ignore
        print(f"   - {len(analysis.remediation_priority)} priority actions") # type: ignore
        
        # Show sample fixes
        issues_with_patches = [i for i in analysis.issues if i.fix and i.fix.patch] # type: ignore
        if issues_with_patches:
            print(f"   - {len(issues_with_patches)} issues have code patches")
        
        return analysis # type: ignore
        
    except Exception as e:
        print(f"\n❌ LLM Analysis failed: {e}")
        raise


def format_sast_findings_with_code(vulnerabilities: List[Dict], project_path: str) -> str:
    if not vulnerabilities:
        return "No SAST issues found."
    
    formatted = []
    for idx, vuln in enumerate(vulnerabilities, 1):
        entry = f"\n{'='*50}\nISSUE #{idx}: {vuln.get('check_id', 'Unknown')}"
        entry += f"\nSeverity: {vuln.get('severity', 'N/A')}"
        entry += f"\nMessage: {vuln.get('message', 'N/A')}"
        
        file_path = vuln.get('path', '')
        line_num = vuln.get('line', vuln.get('start', {}).get('line'))
        
        if file_path:
            entry += f"\nFile: {file_path}"
        if line_num:
            entry += f"\nLine: {line_num}"
            
            # READ ACTUAL CODE SNIPPET
            code_snippet = extract_code_snippet(
                os.path.join(project_path, file_path) if not os.path.isabs(file_path) else file_path,
                line_num,
                context_lines=3
            )
            if code_snippet:
                entry += f"\n\nVULNERABLE CODE:\n{code_snippet}"
        
        # Include extra metadata if available
        if 'extra' in vuln:
            extra = vuln['extra']
            if 'lines' in extra:
                entry += f"\n\nFULL CODE BLOCK:\n{extra['lines']}"
            if 'metadata' in extra:
                metadata = extra['metadata']
                if 'cwe' in metadata:
                    entry += f"\nCWE: {metadata['cwe']}"
                if 'owasp' in metadata:
                    entry += f"\nOWASP: {metadata['owasp']}"
        
        formatted.append(entry)
    
    return "\n".join(formatted)


def extract_code_snippet(file_path: str, line_num: int, context_lines: int = 3) -> str:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        
        snippet = []
        for i in range(start, end):
            line_marker = ">>> " if i == line_num - 1 else "    "
            snippet.append(f"{line_marker}{i+1:4d} | {lines[i].rstrip()}")
        
        return "\n".join(snippet)
    except Exception as e:
        return f"(Could not read code: {e})"


def format_sca_findings(vulnerabilities: List[Dict]) -> str:
    if not vulnerabilities:
        return "No SCA issues found."
    
    formatted = []
    for idx, vuln in enumerate(vulnerabilities, 1):
        entry = f"\n{'='*50}\nDEPENDENCY #{idx}: {vuln.get('title', 'Unknown vulnerability')}"
        entry += f"\nSeverity: {vuln.get('severity', 'N/A')}"
        
        package = vuln.get('package', vuln.get('packageName', 'N/A'))
        version = vuln.get('version', 'N/A')
        entry += f"\nPackage: {package} @ {version}"
        
        # Upgrade path
        fixed_in = vuln.get('fixed_in', vuln.get('fixedIn'))
        if fixed_in:
            entry += f"\n✅ FIX AVAILABLE: Upgrade to {fixed_in}"
            entry += f"\n   Command: pip install {package}=={fixed_in}"
        else:
            entry += f"\n⚠️  NO FIX AVAILABLE - Consider replacing this library"
        
        # CVE info
        if 'identifiers' in vuln:
            identifiers = vuln['identifiers']
            cves = []
            
            if isinstance(identifiers, list) and identifiers:
                if isinstance(identifiers[0], dict):
                    cves = [i.get('value') for i in identifiers if i.get('type') == 'CVE']
                elif isinstance(identifiers[0], str):
                    cves = [i for i in identifiers if 'CVE' in i]
            
            if cves:
                entry += f"\nCVE: {', '.join(cves)}"
        
        formatted.append(entry)
    
    return "\n".join(formatted)