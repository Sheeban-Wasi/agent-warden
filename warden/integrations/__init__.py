"""
Warden Integrations - Framework adapters (The Spokes).

Thin wrappers that connect specific frameworks to Warden Core.
Each integration imports from core, never the reverse.

Available integrations:
- strands: AWS Strands @guard decorator
- langchain: LangChain middleware (coming soon)
"""

# Strands integration (always available - no extra dependencies)
from warden.integrations.strands import guard, ToolGuard, GuardConfig

__all__ = [
    "guard",
    "ToolGuard",
    "GuardConfig",
]
