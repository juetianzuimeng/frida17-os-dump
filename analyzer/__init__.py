# -*- coding: utf-8 -*-
"""
IPA 静态安全分析与 Tweak 自动化生成工具模块
"""

from .ipa_parser import IPAParser, AppPackageInfo
from .macho_parser import MachOParser
from .objc_parser import ObjCParser, ObjCClass, ObjCCategory, ObjCMethod, ObjCMetadata
from .xref_scanner import XrefScanner, XrefReport, XrefResult
from .demangler import SwiftDemangler, UniversalDemangler
from .cpp_demangler import CppDemangler
from .disassembler import Disassembler, DisasmInstruction, DisasmFunction
from .call_graph import CallGraphAnalyzer, CallEdge, CallGraphReport
from .tracer_generator import TracerGenerator
from .sig_maker import SigMaker, SigMatchResult
from .cfg_analyzer import CFGAnalyzer, ControlFlowGraph, BasicBlock
from .engine import AnalysisEngine, AnalysisResult, AnalysisSummary
from .reporter import ConsoleReporter, JSONReporter, MarkdownReporter, HTMLReporter
from .tweak_generator import TweakGenerator

__all__ = [
    "IPAParser",
    "AppPackageInfo",
    "MachOParser",
    "ObjCParser",
    "ObjCClass",
    "ObjCCategory",
    "ObjCMethod",
    "ObjCMetadata",
    "XrefScanner",
    "XrefReport",
    "XrefResult",
    "SwiftDemangler",
    "CppDemangler",
    "UniversalDemangler",
    "Disassembler",
    "DisasmInstruction",
    "DisasmFunction",
    "CallGraphAnalyzer",
    "CallEdge",
    "CallGraphReport",
    "TracerGenerator",
    "SigMaker",
    "SigMatchResult",
    "CFGAnalyzer",
    "ControlFlowGraph",
    "BasicBlock",
    "AnalysisEngine",
    "AnalysisResult",
    "AnalysisSummary",
    "ConsoleReporter",
    "JSONReporter",
    "MarkdownReporter",
    "HTMLReporter",
    "TweakGenerator"
]
