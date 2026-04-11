#!/usr/bin/env python3
"""
Bittensor Agent Security Screener
Validates agent.py files before execution in validator process
Detects: malicious code, static responses, network abuse, resource attacks
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import hashlib


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"  # Block execution immediately
    HIGH = "HIGH"          # Very suspicious, manual review required
    MEDIUM = "MEDIUM"      # Potentially risky, proceed with caution
    LOW = "LOW"            # Minor concerns
    INFO = "INFO"          # Informational only


@dataclass
class SecurityFinding:
    risk_level: RiskLevel
    category: str
    description: str
    line_number: int = None
    code_snippet: str = None
    recommendation: str = None


class AgentScreener:
    """
    Comprehensive security screener for Bittensor agent.py files.
    Focuses on:
    1. Malicious code detection
    2. Static response detection
    3. Network/resource abuse
    4. Code execution safety
    """
    
    # CRITICAL: Absolutely banned - indicates malicious intent
    CRITICAL_PATTERNS = {
        'os.system': 'Direct shell command execution',
        'subprocess.call': 'Subprocess execution without validation',
        'subprocess.Popen': 'Process spawning detected',
        'eval(': 'Dynamic code evaluation',
        'exec(': 'Dynamic code execution',
        '__import__': 'Dynamic import injection',
        'compile(': 'Runtime code compilation',
        'pickle.loads': 'Unsafe deserialization',
        'marshal.loads': 'Unsafe deserialization',
        'shelve.': 'Persistent object storage',
        'ctypes': 'Low-level memory access',
        'cffi': 'Foreign function interface',
        'importlib.import_module': 'Dynamic module loading',
        'sys.modules': 'Module manipulation',
        '__builtins__': 'Builtin manipulation',
        'globals()': 'Global scope manipulation',
        'locals()': 'Local scope manipulation',
        'setattr': 'Dynamic attribute modification',
        'delattr': 'Attribute deletion',
        '__code__': 'Code object access',
        '__globals__': 'Global namespace access',
    }
    
    # HIGH: File system manipulation (suspicious for an agent)
    FILESYSTEM_PATTERNS = {
        'os.remove': 'File deletion',
        'os.rmdir': 'Directory deletion',
        'os.unlink': 'File unlinking',
        'shutil.rmtree': 'Recursive directory deletion',
        'open(': 'File operations (check if writing)',
        'Path.unlink': 'File deletion via pathlib',
        'Path.rmdir': 'Directory deletion via pathlib',
        'os.chmod': 'Permission modification',
        'os.chown': 'Ownership modification',
    }
    
    # MEDIUM: Network operations (can be abused)
    NETWORK_PATTERNS = {
        'socket.': 'Raw socket operations',
        'smtplib': 'Email sending',
        'ftplib': 'FTP operations',
        'telnetlib': 'Telnet operations',
        'paramiko': 'SSH operations',
        'requests.post': 'HTTP POST (check destination)',
        'urllib.request.urlopen': 'URL opening',
        'websocket': 'WebSocket connections',
    }
    
    # Static response indicators (gaming the system)
    STATIC_RESPONSE_INDICATORS = [
        r'return\s*\{[^}]*"findings"\s*:\s*\[\s*\{',  # Hardcoded findings dict
        r'findings\s*=\s*\[\s*\{',  # Hardcoded findings list
        r'"vulnerability_type"\s*:\s*"',  # Hardcoded vulnerability
        r'\.json\s*\(\s*\)',  # Loading from JSON file
        r'with\s+open\(["\'].*\.json["\']',  # Reading JSON file
        r'json\.load\(',  # Loading JSON data
        r'STATIC|HARDCODED|FAKE|DUMMY',  # Suspicious variable names
    ]
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'time.sleep': 'Intentional delays (possible DoS)',
        'while True:': 'Infinite loop detected',
        'os.fork': 'Process forking',
        'multiprocessing.': 'Multiprocessing usage (check if reasonable)',
        'threading.': 'Threading usage (check if reasonable)',
        'sys.exit': 'Program termination',
        'exit(': 'Program termination',
        'quit(': 'Program termination',
        'raise SystemExit': 'System exit',
        'os.environ': 'Environment variable access',
        'getpass.': 'Password/credential access',
        'base64.b64decode': 'Base64 decoding (possible obfuscation)',
        'zlib.decompress': 'Decompression (possible obfuscation)',
    }

    def __init__(self):
        self.findings: List[SecurityFinding] = []
        self.code_lines: List[str] = []
        
    def screen_file(self, agent_path: Path) -> Tuple[bool, List[SecurityFinding]]:
        """
        Main screening function.
        Returns: (is_safe, findings_list)
        """
        self.findings = []
        
        if not agent_path.exists():
            self.findings.append(SecurityFinding(
                risk_level=RiskLevel.CRITICAL,
                category="File Not Found",
                description=f"Agent file does not exist: {agent_path}",
                recommendation="Ensure agent.py exists in repository"
            ))
            return False, self.findings
        
        try:
            with open(agent_path, 'r', encoding='utf-8') as f:
                code = f.read()
                self.code_lines = code.split('\n')
        except Exception as e:
            self.findings.append(SecurityFinding(
                risk_level=RiskLevel.CRITICAL,
                category="File Read Error",
                description=f"Cannot read agent file: {str(e)}",
                recommendation="Check file permissions and encoding"
            ))
            return False, self.findings
        
        # Run all checks
        self._check_critical_patterns(code)
        self._check_filesystem_access(code)
        self._check_network_operations(code)
        self._check_static_responses(code)
        self._check_suspicious_patterns(code)
        self._check_ast_structure(code)
        self._check_main_function(code)
        self._check_imports(code)
        self._check_obfuscation(code)
        
        # Determine if safe to run
        is_safe = self._evaluate_safety()
        
        return is_safe, self.findings
    
    def _check_critical_patterns(self, code: str):
        """Check for absolutely banned patterns"""
        for pattern, description in self.CRITICAL_PATTERNS.items():
            if pattern in code:
                line_num = self._find_line_number(code, pattern)
                self.findings.append(SecurityFinding(
                    risk_level=RiskLevel.CRITICAL,
                    category="Malicious Code",
                    description=f"BANNED PATTERN: {description} ({pattern})",
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(line_num),
                    recommendation="DO NOT RUN - Contains malicious code pattern"
                ))
    
    def _check_filesystem_access(self, code: str):
        """Check for filesystem manipulation"""
        for pattern, description in self.FILESYSTEM_PATTERNS.items():
            if pattern in code:
                line_num = self._find_line_number(code, pattern)
                
                # Special handling for open() - check mode
                if pattern == 'open(':
                    context = self._get_context(line_num, 1)
                    if any(mode in context for mode in ['w', 'a', 'w+', 'a+']):
                        risk = RiskLevel.HIGH
                        desc = f"File writing detected: {description}"
                    else:
                        risk = RiskLevel.MEDIUM
                        desc = f"File reading detected: {description}"
                else:
                    risk = RiskLevel.HIGH
                    desc = description
                
                self.findings.append(SecurityFinding(
                    risk_level=risk,
                    category="Filesystem Access",
                    description=desc,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(line_num),
                    recommendation="Review filesystem operations carefully"
                ))
    
    def _check_network_operations(self, code: str):
        """Check for network operations"""
        for pattern, description in self.NETWORK_PATTERNS.items():
            if pattern in code:
                line_num = self._find_line_number(code, pattern)
                self.findings.append(SecurityFinding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Network Operation",
                    description=f"Network operation: {description}",
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(line_num),
                    recommendation="Verify network destination and rate limiting"
                ))
    
    def _check_static_responses(self, code: str):
        """Detect hardcoded/static responses (gaming the system)"""
        for pattern in self.STATIC_RESPONSE_INDICATORS:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                self.findings.append(SecurityFinding(
                    risk_level=RiskLevel.HIGH,
                    category="Static Response",
                    description="Possible hardcoded/static response detected",
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(line_num),
                    recommendation="Agent may be returning static results without analysis"
                ))
        
        # Check for JSON files in same directory (common static response trick)
        if 'json.load' in code or 'json.loads' in code:
            self.findings.append(SecurityFinding(
                risk_level=RiskLevel.HIGH,
                category="Static Response",
                description="JSON loading detected - may be loading static responses",
                recommendation="Verify agent performs actual analysis, not loading pre-made results"
            ))
    
    def _check_suspicious_patterns(self, code: str):
        """Check for suspicious but not necessarily malicious patterns"""
        for pattern, description in self.SUSPICIOUS_PATTERNS.items():
            if pattern in code:
                line_num = self._find_line_number(code, pattern)
                self.findings.append(SecurityFinding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Suspicious Pattern",
                    description=description,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(line_num),
                    recommendation="Review for legitimate use case"
                ))
    
    def _check_ast_structure(self, code: str):
        """Use AST to check code structure"""
        try:
            tree = ast.parse(code)
            
            # Check for suspicious lambda usage
            for node in ast.walk(tree):
                if isinstance(node, ast.Lambda):
                    self.findings.append(SecurityFinding(
                        risk_level=RiskLevel.LOW,
                        category="Code Structure",
                        description="Lambda function detected (check for obfuscation)",
                        line_number=node.lineno,
                        recommendation="Review lambda functions for clarity"
                    ))
                
                # Check for exec/eval in AST
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec', '__import__', 'compile']:
                            self.findings.append(SecurityFinding(
                                risk_level=RiskLevel.CRITICAL,
                                category="Dynamic Execution",
                                description=f"Dynamic code execution: {node.func.id}",
                                line_number=node.lineno,
                                code_snippet=self._get_code_snippet(node.lineno),
                                recommendation="DO NOT RUN"
                            ))
                
        except SyntaxError as e:
            self.findings.append(SecurityFinding(
                risk_level=RiskLevel.CRITICAL,
                category="Syntax Error",
                description=f"Code has syntax errors: {str(e)}",
                recommendation="Code cannot be parsed - do not run"
            ))
    
    def _check_main_function(self, code: str):
        """Verify main() function exists and has correct signature"""
        if 'def main(' not in code:
            self.findings.append(SecurityFinding(
                risk_level=RiskLevel.CRITICAL,
                category="Missing Function",
                description="No main() function defined",
                recommendation="Agent must define main(tasks, api_key=None)"
            ))
            return
        
        # Check main signature
        main_pattern = r'def\s+main\s*\([^)]*\)'
        match = re.search(main_pattern, code)
        if match:
            signature = match.group(0)
            if 'tasks' not in signature:
                self.findings.append(SecurityFinding(
                    risk_level=RiskLevel.HIGH,
                    category="Invalid Signature",
                    description="main() function missing 'tasks' parameter",
                    recommendation="Function signature should be: main(tasks, api_key=None)"
                ))
    
    def _check_imports(self, code: str):
        """Check import statements for suspicious modules"""
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self._evaluate_import(alias.name, node.lineno)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        self._evaluate_import(node.module, node.lineno)
        except:
            pass
    
    def _evaluate_import(self, module_name: str, line_num: int):
        """Evaluate if an import is suspicious"""
        dangerous_modules = [
            'os', 'subprocess', 'pickle', 'marshal', 'shelve',
            'ctypes', 'cffi', 'importlib', 'imp', 'code',
            'pty', 'telnetlib', 'paramiko'
        ]
        
        if module_name in dangerous_modules:
            # os and subprocess get special treatment
            if module_name in ['os', 'subprocess']:
                self.findings.append(SecurityFinding(
                    risk_level=RiskLevel.MEDIUM,
                    category="Suspicious Import",
                    description=f"Import of '{module_name}' - verify usage is safe",
                    line_number=line_num,
                    recommendation="Check that this module is used safely"
                ))
            else:
                self.findings.append(SecurityFinding(
                    risk_level=RiskLevel.HIGH,
                    category="Dangerous Import",
                    description=f"Dangerous module imported: {module_name}",
                    line_number=line_num,
                    recommendation="Review necessity of this import"
                ))
    
    def _check_obfuscation(self, code: str):
        """Detect code obfuscation attempts"""
        obfuscation_indicators = [
            (r'\\x[0-9a-f]{2}', "Hex-encoded strings (possible obfuscation)"),
            (r'\\[0-9]{3}', "Octal-encoded strings (possible obfuscation)"),
            (r'chr\(\d+\)', "Character code obfuscation"),
            (r'\.encode\(\)\.decode\(', "Encode/decode obfuscation"),
            (r'__[a-z]+__\s*\(', "Dunder method calls (possible tricks)"),
            (r'[a-zA-Z_][a-zA-Z0-9_]{50,}', "Extremely long identifiers (obfuscation)"),
        ]
        
        for pattern, description in obfuscation_indicators:
            if re.search(pattern, code):
                self.findings.append(SecurityFinding(
                    risk_level=RiskLevel.HIGH,
                    category="Obfuscation",
                    description=description,
                    recommendation="Code appears obfuscated - high risk"
                ))
    
    def _find_line_number(self, code: str, pattern: str) -> int:
        """Find line number of pattern in code"""
        index = code.find(pattern)
        if index == -1:
            return None
        return code[:index].count('\n') + 1
    
    def _get_code_snippet(self, line_num: int, context: int = 2) -> str:
        """Get code snippet around line number"""
        if line_num is None or line_num > len(self.code_lines):
            return None
        
        start = max(0, line_num - context - 1)
        end = min(len(self.code_lines), line_num + context)
        
        snippet = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            snippet.append(f"{prefix}{self.code_lines[i]}")
        
        return "\n".join(snippet)
    
    def _get_context(self, line_num: int, num_lines: int) -> str:
        """Get context around a line"""
        if line_num is None or line_num > len(self.code_lines):
            return ""
        
        start = max(0, line_num - num_lines - 1)
        end = min(len(self.code_lines), line_num + num_lines)
        return " ".join(self.code_lines[start:end])
    
    def _evaluate_safety(self) -> bool:
        """Evaluate overall safety based on findings"""
        # Any CRITICAL finding = not safe
        if any(f.risk_level == RiskLevel.CRITICAL for f in self.findings):
            return False
        
        # Multiple HIGH findings = not safe
        high_count = sum(1 for f in self.findings if f.risk_level == RiskLevel.HIGH)
        if high_count >= 3:
            return False
        
        # Single HIGH finding for static response = not safe
        static_high = any(
            f.risk_level == RiskLevel.HIGH and f.category == "Static Response"
            for f in self.findings
        )
        if static_high:
            return False
        
        return True
    
    def generate_report(self) -> str:
        """Generate human-readable security report"""
        report_lines = [
            "=" * 80,
            "AGENT SECURITY SCREENING REPORT",
            "=" * 80,
            ""
        ]
        
        # Summary
        critical = sum(1 for f in self.findings if f.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for f in self.findings if f.risk_level == RiskLevel.HIGH)
        medium = sum(1 for f in self.findings if f.risk_level == RiskLevel.MEDIUM)
        low = sum(1 for f in self.findings if f.risk_level == RiskLevel.LOW)
        
        report_lines.extend([
            f"Total Findings: {len(self.findings)}",
            f"  CRITICAL: {critical}",
            f"  HIGH:     {high}",
            f"  MEDIUM:   {medium}",
            f"  LOW:      {low}",
            ""
        ])
        
        # Safety verdict
        is_safe = self._evaluate_safety()
        verdict = "✓ SAFE TO RUN" if is_safe else "✗ DO NOT RUN"
        report_lines.extend([
            "VERDICT: " + verdict,
            "=" * 80,
            ""
        ])
        
        # Detailed findings
        if self.findings:
            report_lines.append("DETAILED FINDINGS:")
            report_lines.append("-" * 80)
            
            for i, finding in enumerate(self.findings, 1):
                report_lines.extend([
                    f"\n{i}. [{finding.risk_level.value}] {finding.category}",
                    f"   Description: {finding.description}",
                ])
                
                if finding.line_number:
                    report_lines.append(f"   Line: {finding.line_number}")
                
                if finding.recommendation:
                    report_lines.append(f"   Recommendation: {finding.recommendation}")
                
                if finding.code_snippet:
                    report_lines.extend([
                        "   Code:",
                        *[f"   {line}" for line in finding.code_snippet.split('\n')],
                    ])
        else:
            report_lines.append("No security issues found.")
        
        report_lines.extend([
            "",
            "=" * 80,
        ])
        
        return "\n".join(report_lines)


def screen_agent_file(agent_path: str) -> Tuple[bool, str]:
    """
    Convenience function for screening an agent file.
    
    Args:
        agent_path: Path to agent.py file
        
    Returns:
        (is_safe, report_text)
    """
    screener = AgentScreener()
    is_safe, findings = screener.screen_file(Path(agent_path))
    report = screener.generate_report()
    
    return is_safe, report


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python agent_screener.py <path_to_agent.py>")
        sys.exit(1)
    
    agent_path = sys.argv[1]
    is_safe, report = screen_agent_file(agent_path)
    
    print(report)
    
    sys.exit(0 if is_safe else 1)