"""LLM executive summary and its hallucination guard (owner: Shuja)."""

from .summary import generate_summary, template_summary
from .validator import EvidenceIndex, validate_summary

__all__ = ["EvidenceIndex", "generate_summary", "template_summary", "validate_summary"]
