"""
File Access Guard Example.

Demonstrates how to protect file access operations with Agent-Warden's
FileInspector to prevent path traversal, sensitive file exposure, and
other file-based attacks.
"""

from warden import (
    FileInspector,
    check_file,
    inspect_file,
)
from warden.integrations.strands import guard

# =============================================================================
# BASIC USAGE
# =============================================================================

print("=" * 60)
print("FILE ACCESS GUARD - Basic Usage")
print("=" * 60)

# Quick boolean check
print("\n1. Quick safety checks:")
print(f"   /app/data/file.txt: {check_file('/app/data/file.txt', mode='blocklist')}")
print(f"   ../../../etc/passwd: {check_file('../../../etc/passwd')}")
print(f"   /home/.ssh/id_rsa: {check_file('/home/.ssh/id_rsa')}")

# Full inspection with details
print("\n2. Detailed inspection:")
result = inspect_file("../../../etc/passwd")
print(f"   Path: {result.original_path}")
print(f"   Safe: {result.is_safe}")
print(f"   Violations: {[v.value for v in result.violation_types]}")
print(f"   Reason: {result.verdict.reason}")

# =============================================================================
# PATH TRAVERSAL PROTECTION
# =============================================================================

print("\n" + "=" * 60)
print("PATH TRAVERSAL PROTECTION")
print("=" * 60)

traversal_attacks = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..%2f..%2f..%2fetc/passwd",
    "....//....//etc/passwd",
]

print("\nBlocked path traversal attempts:")
for path in traversal_attacks:
    result = inspect_file(path)
    print(f"   {path[:40]:40} -> BLOCKED ({result.verdict.rule})")

# =============================================================================
# SENSITIVE FILE PROTECTION
# =============================================================================

print("\n" + "=" * 60)
print("SENSITIVE FILE PROTECTION")
print("=" * 60)

sensitive_files = [
    "/app/.env",
    "/home/user/.ssh/id_rsa",
    "/project/.git/config",
    "/.aws/credentials",
    "/app/.htpasswd",
]

print("\nBlocked sensitive files:")
for path in sensitive_files:
    result = inspect_file(path)
    status = "BLOCKED" if not result.is_safe else "ALLOWED"
    print(f"   {path:40} -> {status}")

# =============================================================================
# BLOCKED EXTENSIONS
# =============================================================================

print("\n" + "=" * 60)
print("BLOCKED EXTENSIONS")
print("=" * 60)

extension_files = [
    "/app/config.env",
    "/app/server.key",
    "/app/cert.pem",
    "/app/store.p12",
    "/app/data.txt",  # This one should pass
]

print("\nExtension-based blocking:")
for path in extension_files:
    result = inspect_file(path, mode="blocklist")
    status = "BLOCKED" if not result.is_safe else "ALLOWED"
    print(f"   {path:40} -> {status}")

# =============================================================================
# CLOUD METADATA PROTECTION
# =============================================================================

print("\n" + "=" * 60)
print("CLOUD METADATA PROTECTION")
print("=" * 60)

metadata_urls = [
    "http://169.254.169.254/latest/meta-data/",
    "169.254.169.254/user-data",
    "http://100.100.100.200/latest/meta-data",
]

print("\nBlocked cloud metadata endpoints:")
for path in metadata_urls:
    result = inspect_file(path)
    print(f"   {path:50} -> BLOCKED")

# =============================================================================
# GUARD DECORATOR USAGE
# =============================================================================

print("\n" + "=" * 60)
print("@GUARD DECORATOR INTEGRATION")
print("=" * 60)


@guard(
    sql=False,
    file_access=True,
    file_mode="allowlist",
    file_base_directory="/app",
    on_block="return_error",
)
def read_file_content(path: str) -> dict:
    """Read file content with security protection."""
    # In a real app, this would actually read the file
    return {"status": "ok", "content": f"Contents of {path}"}


# Safe path
result = read_file_content("/app/data/report.txt")
print(f"\n1. Safe path /app/data/report.txt:")
print(f"   Result: {result}")

# Path traversal attempt
result = read_file_content("../../../etc/passwd")
print(f"\n2. Path traversal attempt:")
print(f"   Result: {result}")

# Sensitive file attempt
result = read_file_content("/app/.env")
print(f"\n3. Sensitive file attempt:")
print(f"   Result: {result}")

# =============================================================================
# MODES COMPARISON
# =============================================================================

print("\n" + "=" * 60)
print("INSPECTION MODES")
print("=" * 60)

test_path = "/app/data/file.txt"

print(f"\nPath: {test_path}")
print("\nModes comparison:")

for mode in ["strict", "allowlist", "blocklist", "monitor"]:
    inspector = FileInspector(
        mode=mode,
        allowed_paths={"/app/allowed"} if mode == "strict" else None,
        blocked_paths={"/blocked"} if mode in ("allowlist", "blocklist") else None,
    )
    result = inspector.inspect(test_path)
    status = "PASS" if result.is_safe else "BLOCK"
    print(f"   {mode:12} -> {status}")

# =============================================================================
# CUSTOM CONFIGURATION
# =============================================================================

print("\n" + "=" * 60)
print("CUSTOM CONFIGURATION")
print("=" * 60)

# Create inspector with custom settings
custom_inspector = FileInspector(
    mode="allowlist",
    base_directory="/app",
    allowed_paths={"/app/public", "/app/uploads"},
    blocked_paths={"/app/secrets", "/app/admin"},
    blocked_extensions={".exe", ".dll", ".so"},
    sensitive_patterns={"*.secret", "*.private"},
    max_file_size=10 * 1024 * 1024,  # 10MB
)

test_paths = [
    "/app/public/image.png",
    "/app/secrets/config.yaml",
    "/app/uploads/document.pdf",
    "/app/malware.exe",
    "/etc/passwd",
]

print("\nCustom configuration results:")
for path in test_paths:
    result = custom_inspector.inspect(path)
    status = "PASS" if result.is_safe else "BLOCK"
    reason = result.verdict.rule if result.verdict.rule else "passed"
    print(f"   {path:35} -> {status:5} ({reason})")

print("\n" + "=" * 60)
print("File Access Guard protects your agents from file-based attacks!")
print("=" * 60)
