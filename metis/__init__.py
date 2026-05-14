"""
metis — cross-disciplinary macOS binary vulnerability toolchain.

Components
----------
C1 (exploration_technique) : phase-transition-aware symbolic execution path
    ranking via backbone fraction / solver friction scoring.

C6 (c6_taint) : dataflow taint analysis for XPC/mach port vulnerability
    patterns (OOB, UAF, XTYPE). Composes with C1 via ExplorationTechnique.

dimacs_converter : claripy AST → DIMACS CNF bridge used by C1.
backbone_probe   : fast backbone fraction probe used by C1.
"""

from .dimacs_converter import claripy_to_dimacs, state_to_dimacs, DIMACSResult
from .c3_templates import (
    C3TemplateAnalysis,
    C3Result,
    TemplateMatch,
    VulnTemplate,
    TemplateVulnClass,
    TEMPLATE_BANK,
)
from .c2_rmt import (
    C2RMTAnalysis,
    C2Result,
    BinaryRMTScore,
    FunctionScore,
    SpectralMetrics,
    screen_corpus,
)
from .c6_taint import (
    C6Analysis,
    C6Result,
    C6TaintTechnique,
    VulnClass,
    VulnFinding,
    _is_tainted,       # exposed for testing / composition
    _taint_label,
    _fresh_taint,
)

__all__ = [
    # Core bridge
    'claripy_to_dimacs', 'state_to_dimacs', 'DIMACSResult',
    # C3 template matching
    'C3TemplateAnalysis', 'C3Result', 'TemplateMatch', 'VulnTemplate',
    'TemplateVulnClass', 'TEMPLATE_BANK',
    # C2 RMT screener
    'C2RMTAnalysis', 'C2Result', 'BinaryRMTScore', 'FunctionScore',
    'SpectralMetrics', 'screen_corpus',
    # C6 taint
    'C6Analysis', 'C6Result', 'C6TaintTechnique',
    'VulnClass', 'VulnFinding',
    '_is_tainted', '_taint_label', '_fresh_taint',
]

# Lazy imports for C1 components (avoids importing pysat at package load time)
def __getattr__(name):
    if name in ('backbone_probe', 'quick_hardness_score', 'BackboneResult'):
        from . import backbone_probe as bp
        return getattr(bp, name)
    if name == 'HardnessExplorationTechnique':
        from .exploration_technique import HardnessExplorationTechnique
        return HardnessExplorationTechnique
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
