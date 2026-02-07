# ruff: noqa: I001
"""
Shell Command Inspector for Agent-Warden.

Provides security inspection for shell commands, detecting:
- Dangerous commands (rm, sudo, chmod, kill, etc.)
- Command chaining (;, |, &&, ||, &)
- Redirect injection (>, >>, <)
- Command substitution ($(), backticks)
- Reverse shells (/dev/tcp, nc -e)
- Privilege escalation (sudo, su, chmod 777)
- Obfuscation ($IFS, base64, hex encoding)
- Network exfiltration (curl -d @, wget --post-file)

Philosophy: Deny by Default. If uncertain, block.

Example:
    >>> from warden import check_shell, inspect_shell
    >>> check_shell("ls -la")
    True
    >>> result = inspect_shell("rm -rf /")
    >>> result.is_safe
    False
    >>> result.violation_types
    {ShellViolationType.DANGEROUS_COMMAND, ShellViolationType.DANGEROUS_PATTERN}
"""
from __future__ import annotations

import re
import shlex
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, Literal

from warden.core.verdict import Verdict, create_block_verdict, create_pass_verdict


class ShellMode(Enum):
    """
    Shell command inspection modes.

    RESTRICTED: Only allow commands in explicit allowlist (most secure)
    ALLOWLIST: Allow allowlist commands, block dangerous patterns
    BLOCKLIST: Block dangerous commands only, allow everything else
    MONITOR: Log only, don't block (for policy tuning)
    """

    RESTRICTED = "restricted"
    ALLOWLIST = "allowlist"
    BLOCKLIST = "blocklist"
    MONITOR = "monitor"


class ShellViolationType(Enum):
    """Types of shell command violations that can be detected."""

    EMPTY_COMMAND = "empty_command"
    DANGEROUS_COMMAND = "dangerous_command"
    COMMAND_CHAINING = "command_chaining"
    REDIRECT_INJECTION = "redirect_injection"
    COMMAND_SUBSTITUTION = "command_substitution"
    REVERSE_SHELL = "reverse_shell"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_EXFILTRATION = "network_exfiltration"
    OBFUSCATION = "obfuscation"
    DANGEROUS_PATTERN = "dangerous_pattern"
    NOT_IN_ALLOWLIST = "not_in_allowlist"
    IN_BLOCKLIST = "in_blocklist"
    PARSE_ERROR = "parse_error"


@dataclass
class ShellMatch:
    """A single shell command violation found during inspection."""

    violation_type: ShellViolationType
    command: str
    matched_pattern: str | None
    confidence: float = 1.0

    @property
    def description(self) -> str:
        """Human-readable description of the violation."""
        descriptions = {
            ShellViolationType.EMPTY_COMMAND: "Empty or invalid command",
            ShellViolationType.DANGEROUS_COMMAND: f"Dangerous command: {self.matched_pattern}",
            ShellViolationType.COMMAND_CHAINING: f"Command chaining detected: {self.matched_pattern}",
            ShellViolationType.REDIRECT_INJECTION: f"Redirect injection: {self.matched_pattern}",
            ShellViolationType.COMMAND_SUBSTITUTION: f"Command substitution: {self.matched_pattern}",
            ShellViolationType.REVERSE_SHELL: "Reverse shell pattern detected",
            ShellViolationType.PRIVILEGE_ESCALATION: f"Privilege escalation: {self.matched_pattern}",
            ShellViolationType.NETWORK_EXFILTRATION: "Network exfiltration pattern detected",
            ShellViolationType.OBFUSCATION: f"Command obfuscation: {self.matched_pattern}",
            ShellViolationType.DANGEROUS_PATTERN: f"Dangerous pattern: {self.matched_pattern}",
            ShellViolationType.NOT_IN_ALLOWLIST: "Command not in allowlist",
            ShellViolationType.IN_BLOCKLIST: f"Command in blocklist: {self.matched_pattern}",
            ShellViolationType.PARSE_ERROR: "Command failed to parse safely",
        }
        return descriptions.get(self.violation_type, "Unknown violation")


@dataclass
class ShellResult:
    """
    Result of shell command inspection.

    Contains the verdict and details about any violations found.

    Attributes:
        verdict: The security verdict (PASS or BLOCK)
        original_command: The original command that was inspected
        parsed_command: Base command extracted (if parseable)
        parsed_args: Arguments extracted (if parseable)
        findings: List of violations found
    """

    verdict: Verdict
    original_command: str
    parsed_command: str | None
    parsed_args: list[str] = field(default_factory=list)
    findings: list[ShellMatch] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """Check if the command is allowed to execute."""
        return self.verdict.passed

    @property
    def violation_types(self) -> set[ShellViolationType]:
        """Get set of violation types found."""
        return {f.violation_type for f in self.findings}

    def to_audit_log(self) -> dict:
        """Convert to audit log format."""
        log = self.verdict.to_audit_log()
        log["shell_findings"] = [
            {
                "type": f.violation_type.value,
                "command": f.command,
                "pattern": f.matched_pattern,
                "confidence": f.confidence,
            }
            for f in self.findings
        ]
        log["command"] = {
            "original": self.original_command,
            "parsed": self.parsed_command,
            "args": self.parsed_args,
        }
        return log


# Default dangerous commands that should be blocked
DEFAULT_DANGEROUS_COMMANDS: frozenset[str] = frozenset({
    # Destructive commands
    "rm", "shred", "dd", "mkfs", "fdisk", "parted", "wipefs",
    # Privilege escalation
    "sudo", "su", "chmod", "chown", "chgrp", "setfacl", "doas",
    # System control
    "reboot", "shutdown", "halt", "poweroff", "init", "telinit",
    "systemctl", "service",
    # Process control
    "kill", "pkill", "killall",
    # Network tools (exfiltration risk)
    "nc", "netcat", "ncat", "socat", "telnet",
    # Downloads/uploads
    "curl", "wget",
    # Package managers
    "apt", "apt-get", "yum", "dnf", "pacman", "pip", "pip3", "npm", "yarn",
    # Interpreters (arbitrary code execution)
    "python", "python3", "python2", "perl", "ruby", "node", "php",
    "bash", "sh", "zsh", "dash", "csh", "tcsh", "fish", "ksh",
    # File editors (can modify system files)
    "vi", "vim", "nano", "emacs", "ed", "sed", "awk",
    # Archive tools (can overwrite files)
    "tar", "unzip", "gunzip",
    # Mount operations
    "mount", "umount",
    # User management
    "useradd", "userdel", "usermod", "passwd", "groupadd", "groupdel",
    # Cron
    "crontab", "at",
    # SSH
    "ssh", "scp", "sftp",
    # Database tools
    "mysql", "psql", "mongo", "redis-cli",
})

# Safe commands that are typically allowed
DEFAULT_SAFE_COMMANDS: frozenset[str] = frozenset({
    "ls", "cat", "head", "tail", "grep", "find", "wc", "sort", "uniq",
    "echo", "printf", "date", "pwd", "whoami", "hostname", "uname",
    "env", "printenv", "which", "type", "file", "stat", "du", "df",
    "true", "false", "test", "expr", "basename", "dirname", "realpath",
    "cut", "tr", "tee", "xargs", "seq", "yes", "timeout",
    "diff", "cmp", "comm", "join", "paste", "split", "csplit",
    "md5sum", "sha256sum", "sha1sum", "base64",
    "jq", "yq", "xmllint",
})


@dataclass
class ShellInspectorConfig:
    """Configuration for the Shell Inspector."""

    mode: ShellMode = ShellMode.RESTRICTED
    allowed_commands: frozenset[str] = field(default_factory=lambda: DEFAULT_SAFE_COMMANDS)
    blocked_commands: frozenset[str] = field(default_factory=lambda: DEFAULT_DANGEROUS_COMMANDS)
    blocked_patterns: list[str] = field(default_factory=list)
    allow_operators: bool = False
    allowed_operators: frozenset[str] = field(default_factory=frozenset)
    max_command_length: int = 1000
    require_absolute_paths: bool = False
    fail_closed: bool = True


class ShellInspector:
    """
    Shell command security inspector.

    Validates shell commands for security threats including:
    - Dangerous commands (rm, sudo, chmod, etc.)
    - Command chaining (;, |, &&, ||, &)
    - Redirect injection (>, >>, <)
    - Command substitution ($(), backticks)
    - Reverse shells (/dev/tcp, nc -e)
    - Privilege escalation (sudo, su, chmod 777)
    - Obfuscation ($IFS, base64 decode)

    Philosophy: Deny by Default. If uncertain, block.

    Args:
        mode: Inspection mode (restricted, allowlist, blocklist, monitor)
        allowed_commands: Commands explicitly allowed
        blocked_commands: Commands explicitly blocked
        blocked_patterns: Additional regex patterns to block
        allow_operators: Allow shell operators (;, |, &&, etc.)
        allowed_operators: Specific operators to allow if allow_operators is False
        fail_closed: If True, block on parse errors or uncertainty

    Example:
        >>> inspector = ShellInspector(
        ...     mode="restricted",
        ...     allowed_commands={"ls", "cat", "grep"},
        ... )
        >>> result = inspector.inspect("ls -la")
        >>> result.is_safe
        True
        >>> result = inspector.inspect("rm -rf /")
        >>> result.is_safe
        False
    """

    INSPECTOR_NAME = "shell_inspector"

    # Shell operators that enable command chaining
    SHELL_OPERATORS: ClassVar[dict[str, str]] = {
        ";": "sequential_execution",
        "|": "pipe",
        "||": "or_execution",
        "&&": "and_execution",
        "&": "background_execution",
    }

    # Redirect operators
    REDIRECT_OPERATORS: ClassVar[dict[str, str]] = {
        ">": "output_redirect",
        ">>": "append_redirect",
        "<": "input_redirect",
        "2>": "stderr_redirect",
        "2>&1": "stderr_to_stdout",
        "&>": "all_redirect",
        ">&": "fd_redirect",
    }

    # Command substitution patterns
    COMMAND_SUBSTITUTION_PATTERNS: ClassVar[list[re.Pattern]] = [
        re.compile(r"\$\([^)]+\)"),  # $(command)
        re.compile(r"`[^`]+`"),  # `command`
        re.compile(r"\$\{[^}]+\}"),  # ${var} can execute code
    ]

    # Reverse shell patterns
    REVERSE_SHELL_PATTERNS: ClassVar[list[re.Pattern]] = [
        re.compile(r"/dev/tcp/"),
        re.compile(r"/dev/udp/"),
        re.compile(r"bash\s+-i\s+>&"),
        re.compile(r"nc\s+.*-e\s+/bin/"),
        re.compile(r"ncat\s+.*-e\s+/bin/"),
        re.compile(r"mkfifo.*nc.*sh"),
        re.compile(r"mkfifo.*ncat.*sh"),
        re.compile(r"python.*socket.*connect"),
        re.compile(r"perl.*socket.*INET"),
        re.compile(r"ruby.*TCPSocket"),
        re.compile(r"php.*fsockopen"),
    ]

    # Privilege escalation patterns
    PRIVILEGE_ESCALATION_PATTERNS: ClassVar[list[re.Pattern]] = [
        re.compile(r"chmod\s+777"),
        re.compile(r"chmod\s+[0-7]*7[0-7]*7"),  # World writable
        re.compile(r"chmod\s+\+s"),  # SUID/SGID
        re.compile(r"chmod\s+u\+s"),
        re.compile(r"chmod\s+g\+s"),
        re.compile(r"chown\s+root"),
        re.compile(r"chown\s+0:"),
        re.compile(r"setcap"),
        re.compile(r"visudo"),
    ]

    # Dangerous command patterns
    DANGEROUS_PATTERNS: ClassVar[list[re.Pattern]] = [
        # Destructive patterns
        re.compile(r"rm\s+(-[rf]+\s+)*[/*]"),  # rm -rf /
        re.compile(r"rm\s+.*--no-preserve-root"),
        re.compile(r">\s*/dev/[sh]d[a-z]"),  # Overwrite disk
        re.compile(r"dd\s+.*of=/dev/"),  # dd to device
        re.compile(r"mkfs\s+"),  # Format filesystem
        re.compile(r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;"),  # Fork bomb
        re.compile(r">\s*/dev/null\s+2>&1"),  # Can hide malicious output

        # Command injection via pipe to shell
        re.compile(r"\|\s*bash"),
        re.compile(r"\|\s*sh"),
        re.compile(r"\|\s*zsh"),
        re.compile(r"base64\s+-d.*\|"),  # Base64 decode to pipe

        # Eval-style execution
        re.compile(r"eval\s+"),
        re.compile(r"exec\s+"),
        re.compile(r"source\s+"),
        re.compile(r"\.\s+/"),  # Source file

        # Network exfiltration
        re.compile(r"curl\s+.*-d\s+@"),  # POST file contents
        re.compile(r"curl\s+.*--data\s+@"),
        re.compile(r"curl\s+.*-F\s+"),  # Upload file
        re.compile(r"curl\s+.*--upload-file"),
        re.compile(r"wget\s+.*--post-file"),
        re.compile(r"curl.*\|\s*bash"),  # Fetch and execute
        re.compile(r"wget.*\|\s*bash"),

        # Environment manipulation
        re.compile(r"export\s+PATH="),
        re.compile(r"export\s+LD_PRELOAD"),
        re.compile(r"export\s+LD_LIBRARY_PATH"),

        # History manipulation
        re.compile(r"history\s+-c"),
        re.compile(r"unset\s+HISTFILE"),
        re.compile(r"HISTFILE=/dev/null"),
    ]

    # Obfuscation patterns
    OBFUSCATION_PATTERNS: ClassVar[list[re.Pattern]] = [
        re.compile(r"\$IFS"),  # IFS splitting
        re.compile(r"\$\{IFS\}"),
        re.compile(r"\\x[0-9a-fA-F]{2}"),  # Hex encoding
        re.compile(r"\\[0-7]{3}"),  # Octal encoding
        re.compile(r"\$'\\'"),  # $'' quoting with escapes
        re.compile(r"base64\s+-d"),  # Base64 decode
        re.compile(r"xxd\s+-r"),  # Hex decode
        re.compile(r"printf\s+.*\\x"),  # Printf hex
        re.compile(r"echo\s+-e.*\\x"),  # Echo hex
        re.compile(r"\[\[.*=~"),  # Regex in bash (can be tricky)
        re.compile(r"rev\s*\|"),  # Reverse pipe (obfuscation)
    ]

    def __init__(
        self,
        mode: ShellMode | str = ShellMode.RESTRICTED,
        allowed_commands: set[str] | frozenset[str] | list[str] | None = None,
        blocked_commands: set[str] | frozenset[str] | list[str] | None = None,
        blocked_patterns: list[str] | None = None,
        allow_operators: bool = False,
        allowed_operators: set[str] | frozenset[str] | list[str] | None = None,
        max_command_length: int = 1000,
        require_absolute_paths: bool = False,
        fail_closed: bool = True,
    ) -> None:
        """Initialize the ShellInspector with configuration."""
        if isinstance(mode, str):
            mode = ShellMode(mode)

        self.config = ShellInspectorConfig(
            mode=mode,
            allowed_commands=(
                frozenset(allowed_commands) if allowed_commands
                else DEFAULT_SAFE_COMMANDS
            ),
            blocked_commands=(
                frozenset(blocked_commands) if blocked_commands
                else DEFAULT_DANGEROUS_COMMANDS
            ),
            blocked_patterns=blocked_patterns or [],
            allow_operators=allow_operators,
            allowed_operators=(
                frozenset(allowed_operators) if allowed_operators
                else frozenset()
            ),
            max_command_length=max_command_length,
            require_absolute_paths=require_absolute_paths,
            fail_closed=fail_closed,
        )

    def inspect(self, command: str) -> ShellResult:
        """
        Inspect a shell command for security violations.

        Args:
            command: The shell command to inspect

        Returns:
            ShellResult with verdict and violation details
        """
        start_time = time.perf_counter()
        findings: list[ShellMatch] = []

        # Pre-validation: empty command
        if not command or not command.strip():
            return self._create_block_result(
                command=command or "",
                parsed_command=None,
                parsed_args=[],
                findings=[
                    ShellMatch(
                        violation_type=ShellViolationType.EMPTY_COMMAND,
                        command=command or "",
                        matched_pattern="empty",
                    )
                ],
                reason="Empty or whitespace-only command",
                rule="empty_command",
                start_time=start_time,
            )

        # Check command length
        if len(command) > self.config.max_command_length:
            return self._create_block_result(
                command=command,
                parsed_command=None,
                parsed_args=[],
                findings=[
                    ShellMatch(
                        violation_type=ShellViolationType.DANGEROUS_PATTERN,
                        command=command[:100] + "...",
                        matched_pattern=f"length>{self.config.max_command_length}",
                    )
                ],
                reason=f"Command exceeds max length ({self.config.max_command_length})",
                rule="command_too_long",
                start_time=start_time,
            )

        # Check for command chaining operators
        chaining_check = self._check_command_chaining(command)
        if chaining_check:
            findings.append(chaining_check)
            if self.config.mode != ShellMode.MONITOR:
                return self._create_block_result(
                    command=command,
                    parsed_command=None,
                    parsed_args=[],
                    findings=findings,
                    reason=f"Command chaining detected: {chaining_check.matched_pattern}",
                    rule="command_chaining",
                    start_time=start_time,
                )

        # Check for redirect operators
        redirect_check = self._check_redirects(command)
        if redirect_check:
            findings.append(redirect_check)
            if self.config.mode != ShellMode.MONITOR:
                return self._create_block_result(
                    command=command,
                    parsed_command=None,
                    parsed_args=[],
                    findings=findings,
                    reason=f"Redirect injection: {redirect_check.matched_pattern}",
                    rule="redirect_injection",
                    start_time=start_time,
                )

        # Check for command substitution
        subst_check = self._check_command_substitution(command)
        if subst_check:
            findings.append(subst_check)
            if self.config.mode != ShellMode.MONITOR:
                return self._create_block_result(
                    command=command,
                    parsed_command=None,
                    parsed_args=[],
                    findings=findings,
                    reason=f"Command substitution detected: {subst_check.matched_pattern}",
                    rule="command_substitution",
                    start_time=start_time,
                )

        # Check for reverse shell patterns
        reverse_check = self._check_reverse_shell(command)
        if reverse_check:
            findings.append(reverse_check)
            if self.config.mode != ShellMode.MONITOR:
                return self._create_block_result(
                    command=command,
                    parsed_command=None,
                    parsed_args=[],
                    findings=findings,
                    reason="Reverse shell pattern detected",
                    rule="reverse_shell",
                    start_time=start_time,
                )

        # Check for privilege escalation patterns
        priv_check = self._check_privilege_escalation(command)
        if priv_check:
            findings.append(priv_check)
            if self.config.mode != ShellMode.MONITOR:
                return self._create_block_result(
                    command=command,
                    parsed_command=None,
                    parsed_args=[],
                    findings=findings,
                    reason=f"Privilege escalation: {priv_check.matched_pattern}",
                    rule="privilege_escalation",
                    start_time=start_time,
                )

        # Check for dangerous patterns
        pattern_check = self._check_dangerous_patterns(command)
        if pattern_check:
            findings.append(pattern_check)
            if self.config.mode != ShellMode.MONITOR:
                return self._create_block_result(
                    command=command,
                    parsed_command=None,
                    parsed_args=[],
                    findings=findings,
                    reason=f"Dangerous pattern: {pattern_check.matched_pattern}",
                    rule="dangerous_pattern",
                    start_time=start_time,
                )

        # Check for obfuscation
        obfuscation_check = self._check_obfuscation(command)
        if obfuscation_check:
            findings.append(obfuscation_check)
            if self.config.mode != ShellMode.MONITOR:
                return self._create_block_result(
                    command=command,
                    parsed_command=None,
                    parsed_args=[],
                    findings=findings,
                    reason=f"Command obfuscation: {obfuscation_check.matched_pattern}",
                    rule="obfuscation",
                    start_time=start_time,
                )

        # Check custom blocked patterns
        custom_check = self._check_custom_patterns(command)
        if custom_check:
            findings.append(custom_check)
            if self.config.mode != ShellMode.MONITOR:
                return self._create_block_result(
                    command=command,
                    parsed_command=None,
                    parsed_args=[],
                    findings=findings,
                    reason=f"Blocked pattern: {custom_check.matched_pattern}",
                    rule="custom_blocked_pattern",
                    start_time=start_time,
                )

        # Try to parse the command
        parsed_command, parsed_args = self._parse_command(command)

        if parsed_command is None:
            if self.config.fail_closed:
                return self._create_block_result(
                    command=command,
                    parsed_command=None,
                    parsed_args=[],
                    findings=[
                        ShellMatch(
                            violation_type=ShellViolationType.PARSE_ERROR,
                            command=command,
                            matched_pattern="parse_failed",
                        )
                    ],
                    reason="Command failed to parse safely",
                    rule="parse_error",
                    start_time=start_time,
                )

        # Check if base command is in blocklist
        if parsed_command.lower() in {c.lower() for c in self.config.blocked_commands}:
            findings.append(
                ShellMatch(
                    violation_type=ShellViolationType.DANGEROUS_COMMAND,
                    command=command,
                    matched_pattern=parsed_command,
                )
            )
            if self.config.mode != ShellMode.MONITOR:
                return self._create_block_result(
                    command=command,
                    parsed_command=parsed_command,
                    parsed_args=parsed_args,
                    findings=findings,
                    reason=f"Dangerous command blocked: {parsed_command}",
                    rule="dangerous_command",
                    start_time=start_time,
                )

        # Mode-specific checks
        if self.config.mode == ShellMode.RESTRICTED:
            # In restricted mode, only allowlist commands are permitted
            if parsed_command.lower() not in {c.lower() for c in self.config.allowed_commands}:
                findings.append(
                    ShellMatch(
                        violation_type=ShellViolationType.NOT_IN_ALLOWLIST,
                        command=command,
                        matched_pattern=parsed_command,
                    )
                )
                return self._create_block_result(
                    command=command,
                    parsed_command=parsed_command,
                    parsed_args=parsed_args,
                    findings=findings,
                    reason=f"Command not in allowlist: {parsed_command}",
                    rule="not_in_allowlist",
                    start_time=start_time,
                )

        elif self.config.mode == ShellMode.ALLOWLIST:
            # In allowlist mode, check blocklist first, then allow if in allowlist
            # Blocklist was already checked above
            pass

        elif self.config.mode == ShellMode.BLOCKLIST:
            # In blocklist mode, only blocklist matters
            # Already checked above
            pass

        # MONITOR mode: log but allow
        if self.config.mode == ShellMode.MONITOR and findings:
            return ShellResult(
                verdict=create_pass_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason=f"Command allowed (monitor mode) with {len(findings)} finding(s)",
                    latency_ms=self._elapsed_ms(start_time),
                ),
                original_command=command,
                parsed_command=parsed_command,
                parsed_args=parsed_args,
                findings=findings,
            )

        # All checks passed
        return ShellResult(
            verdict=create_pass_verdict(
                inspector=self.INSPECTOR_NAME,
                reason="Command passed all security checks",
                latency_ms=self._elapsed_ms(start_time),
            ),
            original_command=command,
            parsed_command=parsed_command,
            parsed_args=parsed_args,
            findings=[],
        )

    def _parse_command(self, command: str) -> tuple[str | None, list[str]]:
        """Parse command into base command and arguments."""
        try:
            parts = shlex.split(command)
            if not parts:
                return None, []
            # Handle path prefixed commands like /bin/ls
            base_cmd = parts[0].split("/")[-1] if "/" in parts[0] else parts[0]
            return base_cmd, parts[1:]
        except ValueError:
            # shlex.split can raise ValueError on malformed input
            return None, []

    def _check_command_chaining(self, command: str) -> ShellMatch | None:
        """Check for command chaining operators."""
        if self.config.allow_operators:
            return None

        for op, op_type in self.SHELL_OPERATORS.items():
            # Skip if operator is explicitly allowed
            if op in self.config.allowed_operators:
                continue

            # Check for operator (with some context to avoid false positives)
            if op == "&":
                # Avoid matching && when looking for &
                if re.search(r"(?<!&)&(?!&)", command):
                    return ShellMatch(
                        violation_type=ShellViolationType.COMMAND_CHAINING,
                        command=command,
                        matched_pattern=f"{op} ({op_type})",
                    )
            elif op in command:
                return ShellMatch(
                    violation_type=ShellViolationType.COMMAND_CHAINING,
                    command=command,
                    matched_pattern=f"{op} ({op_type})",
                )
        return None

    def _check_redirects(self, command: str) -> ShellMatch | None:
        """Check for redirect operators."""
        if self.config.allow_operators:
            return None

        for op, op_type in self.REDIRECT_OPERATORS.items():
            if op in self.config.allowed_operators:
                continue

            # Use word boundary to avoid false positives
            if op == ">":
                # Match > but not >> or 2> or &>
                if re.search(r"(?<![2&>])>(?!>)", command):
                    return ShellMatch(
                        violation_type=ShellViolationType.REDIRECT_INJECTION,
                        command=command,
                        matched_pattern=f"{op} ({op_type})",
                    )
            elif op in command:
                return ShellMatch(
                    violation_type=ShellViolationType.REDIRECT_INJECTION,
                    command=command,
                    matched_pattern=f"{op} ({op_type})",
                )
        return None

    def _check_command_substitution(self, command: str) -> ShellMatch | None:
        """Check for command substitution patterns."""
        for pattern in self.COMMAND_SUBSTITUTION_PATTERNS:
            match = pattern.search(command)
            if match:
                return ShellMatch(
                    violation_type=ShellViolationType.COMMAND_SUBSTITUTION,
                    command=command,
                    matched_pattern=match.group()[:50],
                )
        return None

    def _check_reverse_shell(self, command: str) -> ShellMatch | None:
        """Check for reverse shell patterns."""
        for pattern in self.REVERSE_SHELL_PATTERNS:
            if pattern.search(command):
                return ShellMatch(
                    violation_type=ShellViolationType.REVERSE_SHELL,
                    command=command,
                    matched_pattern=pattern.pattern[:50],
                )
        return None

    def _check_privilege_escalation(self, command: str) -> ShellMatch | None:
        """Check for privilege escalation patterns."""
        for pattern in self.PRIVILEGE_ESCALATION_PATTERNS:
            if pattern.search(command):
                return ShellMatch(
                    violation_type=ShellViolationType.PRIVILEGE_ESCALATION,
                    command=command,
                    matched_pattern=pattern.pattern[:50],
                )
        return None

    def _check_dangerous_patterns(self, command: str) -> ShellMatch | None:
        """Check for dangerous command patterns."""
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern.search(command):
                return ShellMatch(
                    violation_type=ShellViolationType.DANGEROUS_PATTERN,
                    command=command,
                    matched_pattern=pattern.pattern[:50],
                )
        return None

    def _check_obfuscation(self, command: str) -> ShellMatch | None:
        """Check for command obfuscation patterns."""
        for pattern in self.OBFUSCATION_PATTERNS:
            if pattern.search(command):
                return ShellMatch(
                    violation_type=ShellViolationType.OBFUSCATION,
                    command=command,
                    matched_pattern=pattern.pattern[:50],
                )
        return None

    def _check_custom_patterns(self, command: str) -> ShellMatch | None:
        """Check custom blocked patterns."""
        for pattern_str in self.config.blocked_patterns:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                if pattern.search(command):
                    return ShellMatch(
                        violation_type=ShellViolationType.DANGEROUS_PATTERN,
                        command=command,
                        matched_pattern=pattern_str[:50],
                    )
            except re.error:
                # Invalid regex, treat as literal string
                if pattern_str.lower() in command.lower():
                    return ShellMatch(
                        violation_type=ShellViolationType.DANGEROUS_PATTERN,
                        command=command,
                        matched_pattern=pattern_str[:50],
                    )
        return None

    def _create_block_result(
        self,
        command: str,
        parsed_command: str | None,
        parsed_args: list[str],
        findings: list[ShellMatch],
        reason: str,
        rule: str,
        start_time: float,
    ) -> ShellResult:
        """Create a blocked result."""
        return ShellResult(
            verdict=create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=reason,
                rule=rule,
                details={
                    "command": command[:200],
                    "parsed_command": parsed_command,
                    "violation_count": len(findings),
                },
                latency_ms=self._elapsed_ms(start_time),
            ),
            original_command=command,
            parsed_command=parsed_command,
            parsed_args=parsed_args,
            findings=findings,
        )

    def _elapsed_ms(self, start_time: float) -> float:
        """Calculate elapsed time in milliseconds."""
        return (time.perf_counter() - start_time) * 1000


# Convenience functions


def check_shell(
    command: str,
    mode: Literal["restricted", "allowlist", "blocklist", "monitor"] = "restricted",
    allowed_commands: list[str] | None = None,
    blocked_commands: list[str] | None = None,
) -> bool:
    """
    Quick check if a shell command is safe to execute.

    Args:
        command: Shell command to check
        mode: Inspection mode (default: restricted)
        allowed_commands: Commands explicitly allowed
        blocked_commands: Commands explicitly blocked

    Returns:
        True if command is safe, False if blocked

    Example:
        >>> if check_shell("ls -la"):
        ...     subprocess.run(command, shell=True)
        ... else:
        ...     raise SecurityError("Command blocked")
    """
    inspector = ShellInspector(
        mode=mode,
        allowed_commands=set(allowed_commands) if allowed_commands else None,
        blocked_commands=set(blocked_commands) if blocked_commands else None,
    )
    result = inspector.inspect(command)
    return result.is_safe


def inspect_shell(
    command: str,
    mode: Literal["restricted", "allowlist", "blocklist", "monitor"] = "restricted",
    allowed_commands: list[str] | None = None,
    blocked_commands: list[str] | None = None,
    blocked_patterns: list[str] | None = None,
    allow_operators: bool = False,
) -> ShellResult:
    """
    Inspect a shell command and get full result details.

    Use this when you need the audit trail or detailed violation info.

    Args:
        command: Shell command to inspect
        mode: Inspection mode
        allowed_commands: Commands explicitly allowed
        blocked_commands: Commands explicitly blocked
        blocked_patterns: Additional regex patterns to block
        allow_operators: Allow shell operators (;, |, &&, etc.)

    Returns:
        ShellResult with verdict and violation details

    Example:
        >>> result = inspect_shell("rm -rf /")
        >>> if not result.is_safe:
        ...     logger.warning(result.to_audit_log())
        ...     raise SecurityError(result.verdict.reason)
    """
    inspector = ShellInspector(
        mode=mode,
        allowed_commands=set(allowed_commands) if allowed_commands else None,
        blocked_commands=set(blocked_commands) if blocked_commands else None,
        blocked_patterns=blocked_patterns,
        allow_operators=allow_operators,
    )
    return inspector.inspect(command)
