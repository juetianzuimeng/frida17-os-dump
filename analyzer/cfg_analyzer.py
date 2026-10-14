# -*- coding: utf-8 -*-
"""
ARM64 函数控制流图分析器与基本块切分器 (Control Flow Graph & Basic Block Analyzer)

基于纯算法解析 ARM64 指令分支流，将函数汇编切分为基本块 (Basic Blocks)，
构建控制流边 (True/False/Direct 分支)，并支持控制台结构化输出与 Mermaid 流程图导出。
"""

import os
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from .disassembler import Disassembler, DisasmInstruction


@dataclass
class BasicBlock:
    """基本块 (Basic Block)"""
    id: int                                                 # 块编号 (0, 1, 2...)
    start_va: int                                           # 块起始地址 (VA)
    end_va: int                                             # 块结束地址 (VA, 包含最后一条指令末尾)
    instructions: List[DisasmInstruction] = field(default_factory=list)
    successors: List[Tuple[int, str]] = field(default_factory=list) # [(block_id, "true"|"false"|"direct")]
    predecessors: List[int] = field(default_factory=list)   # 上游前驱块 id 列表
    is_exit: bool = False                                   # 是否为函数返回出口块 (RET)


@dataclass
class ControlFlowGraph:
    """函数控制流图 (CFG)"""
    function_va: int
    function_label: str
    blocks: List[BasicBlock] = field(default_factory=list)


class CFGAnalyzer:
    """ARM64 函数控制流图分析引擎"""

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)
        self.disassembler = Disassembler(self.file_path)

    def analyze_function(
        self,
        target_va_or_offset: int,
        max_instructions: int = 150
    ) -> ControlFlowGraph:
        """分析指定函数，切分基本块并构建控制流图"""
        self.disassembler.initialize()
        va, _ = self.disassembler._normalize_address(target_va_or_offset)
        fva = self.disassembler._nearest_func_start(va)

        # 1. 线性反汇编该函数代码段
        disasm_func = self.disassembler.disasm_at(
            fva,
            max_instructions=max_instructions,
            stop_at_ret=False
        )

        instructions = disasm_func.instructions
        if not instructions:
            return ControlFlowGraph(function_va=fva, function_label=f"func@0x{fva:X}")

        # 2. 识别所有基本块入口点 (Leaders)
        leaders = {fva}
        insn_map: Dict[int, DisasmInstruction] = {}
        branch_targets: Dict[int, Tuple[str, List[int]]] = {} # addr -> (branch_type, [target_addrs])

        for i, insn in enumerate(instructions):
            addr = insn.address
            insn_map[addr] = insn
            b_type, targets = self._decode_branch(insn)
            if b_type:
                branch_targets[addr] = (b_type, targets)
                # 分支目标均为 Leader
                for t in targets:
                    leaders.add(t)
                # 分支指令紧随的下一条指令也是 Leader
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].address)
            elif insn.mnemonic in ("ret", "retab"):
                # RET 之后的指令若存在，也是 Leader
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].address)

        # 过滤仅落在当前反汇编范围内的 Leader 并排序
        min_addr = instructions[0].address
        max_addr = instructions[-1].address
        valid_leaders = sorted([l for l in leaders if min_addr <= l <= max_addr])

        # 3. 按 Leader 划分基本块
        blocks: List[BasicBlock] = []
        va_to_block_id: Dict[int, int] = {}

        for b_idx, leader_va in enumerate(valid_leaders):
            next_leader = valid_leaders[b_idx + 1] if b_idx + 1 < len(valid_leaders) else (max_addr + 4)
            block_insns = [insn for insn in instructions if leader_va <= insn.address < next_leader]
            if not block_insns:
                continue

            end_va = block_insns[-1].address + 4
            is_exit = any(insn.mnemonic in ("ret", "retab") for insn in block_insns)

            bb = BasicBlock(
                id=len(blocks),
                start_va=leader_va,
                end_va=end_va,
                instructions=block_insns,
                is_exit=is_exit
            )
            va_to_block_id[leader_va] = bb.id
            blocks.append(bb)

        # 4. 构建控制流后继与前驱边 (CFG Edges)
        for bb in blocks:
            if not bb.instructions:
                continue
            last_insn = bb.instructions[-1]
            last_addr = last_insn.address

            if last_addr in branch_targets:
                b_type, targets = branch_targets[last_addr]
                if b_type == "cond":
                    # 条件跳转: targets[0] 为 True 目标, targets[1] 为 False 跌落地址
                    true_target = targets[0]
                    false_target = targets[1]
                    if true_target in va_to_block_id:
                        t_id = va_to_block_id[true_target]
                        bb.successors.append((t_id, "true"))
                        blocks[t_id].predecessors.append(bb.id)
                    if false_target in va_to_block_id:
                        f_id = va_to_block_id[false_target]
                        bb.successors.append((f_id, "false"))
                        blocks[f_id].predecessors.append(bb.id)
                elif b_type == "direct":
                    # 无条件跳转: targets[0] 为目标
                    t_target = targets[0]
                    if t_target in va_to_block_id:
                        t_id = va_to_block_id[t_target]
                        bb.successors.append((t_id, "direct"))
                        blocks[t_id].predecessors.append(bb.id)
            elif not bb.is_exit:
                # 普通跌落至下一个顺序 BasicBlock
                next_addr = bb.end_va
                if next_addr in va_to_block_id:
                    next_id = va_to_block_id[next_addr]
                    bb.successors.append((next_id, "direct"))
                    blocks[next_id].predecessors.append(bb.id)

        return ControlFlowGraph(
            function_va=fva,
            function_label=f"func@0x{fva:X}",
            blocks=blocks
        )

    @staticmethod
    def _decode_branch(insn: DisasmInstruction) -> Tuple[Optional[str], List[int]]:
        """
        解码分支指令目标地址。
        返回: (branch_type, [target_addresses])
        branch_type: 'cond' (条件跳转) | 'direct' (无条件跳转) | None
        """
        m = insn.mnemonic
        addr = insn.address
        raw = bytes.fromhex(insn.bytes_hex)
        if len(raw) < 4:
            return (None, [])
        word = struct.unpack("<I", raw)[0]

        # 1. B.cond
        if (word >> 24) & 0xFF == 0x54:
            imm19 = (word >> 5) & 0x7FFFF
            if imm19 & (1 << 18): imm19 -= (1 << 19)
            target = addr + imm19 * 4
            return ("cond", [target, addr + 4])

        # 2. CBZ / CBNZ
        if (word & 0x7E000000) == 0x34000000:
            imm19 = (word >> 5) & 0x7FFFF
            if imm19 & (1 << 18): imm19 -= (1 << 19)
            target = addr + imm19 * 4
            return ("cond", [target, addr + 4])

        # 3. TBZ / TBNZ
        if (word & 0x7E000000) == 0x36000000:
            imm14 = (word >> 5) & 0x3FFF
            if imm14 & (1 << 13): imm14 -= (1 << 14)
            target = addr + imm14 * 4
            return ("cond", [target, addr + 4])

        # 4. B (无条件直接跳转)
        if (word >> 26) & 0x3F == 0x05:
            imm26 = word & 0x03FFFFFF
            if imm26 & (1 << 25): imm26 -= (1 << 26)
            target = addr + imm26 * 4
            return ("direct", [target])

        return (None, [])

    @classmethod
    def format_console_cfg(cls, cfg: ControlFlowGraph) -> List[str]:
        """格式化为控制台基本块结构图"""
        lines = [
            f"\033[1;35m=== [CFG] {cfg.function_label} 控制流图 (共 {len(cfg.blocks)} 个基本块) ===\033[0m"
        ]

        for bb in cfg.blocks:
            succ_str = ", ".join(f"BB_{s_id}({s_type})" for s_id, s_type in bb.successors) or ("RET / 出口" if bb.is_exit else "无")
            pred_str = ", ".join(f"BB_{p_id}" for p_id in bb.predecessors) or "入口"

            lines.append("")
            lines.append(f"\033[1;36m[Block {bb.id}]\033[0m \033[90m(0x{bb.start_va:X} ~ 0x{bb.end_va:X}, {len(bb.instructions)} 条指令)\033[0m")
            lines.append(f"  \033[93m上游前驱:\033[0m {pred_str}  \033[92m下游分支:\033[0m {succ_str}")

            for insn in bb.instructions:
                comm = f"  \033[90m; {insn.comment}\033[0m" if insn.comment else ""
                lines.append(f"    0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str:<26}{comm}")

        return lines

    @classmethod
    def format_mermaid_cfg(cls, cfg: ControlFlowGraph) -> str:
        """导出为 Markdown Mermaid 流程图"""
        lines = [
            "```mermaid",
            "---",
            f"title: 控制流图 (CFG) - {cfg.function_label}",
            "---",
            "graph TD",
            "    %% Styles",
            "    classDef entryBlock fill:#2E7D32,stroke:#1B5E20,stroke-width:2px,color:#fff;",
            "    classDef normalBlock fill:#263238,stroke:#455A64,stroke-width:1px,color:#ECEFF1;",
            "    classDef exitBlock fill:#C62828,stroke:#8E0000,stroke-width:2px,color:#fff;",
            ""
        ]

        # 声明各基本块节点
        for bb in cfg.blocks:
            code_lines = []
            for insn in bb.instructions[:6]: # 节点内最多内联展示 6 条关键指令
                code_lines.append(f"{insn.mnemonic} {insn.op_str}")
            if len(bb.instructions) > 6:
                code_lines.append(f"... 还有 {len(bb.instructions)-6} 条指令")

            block_content = f"<b>Block {bb.id}</b> [0x{bb.start_va:X}]<br/>" + "<br/>".join(code_lines)
            safe_content = block_content.replace('"', '&quot;')
            lines.append(f'    BB_{bb.id}["{safe_content}"]')

            if bb.id == 0:
                lines.append(f"    class BB_{bb.id} entryBlock;")
            elif bb.is_exit:
                lines.append(f"    class BB_{bb.id} exitBlock;")
            else:
                lines.append(f"    class BB_{bb.id} normalBlock;")

        lines.append("")

        # 声明分支边
        for bb in cfg.blocks:
            for s_id, s_type in bb.successors:
                if s_type == "true":
                    lines.append(f'    BB_{bb.id} -->|"True (条件达成)"| BB_{s_id}')
                elif s_type == "false":
                    lines.append(f'    BB_{bb.id} -->|"False (条件未成)"| BB_{s_id}')
                else:
                    lines.append(f'    BB_{bb.id} -->|"Jump"| BB_{s_id}')

        lines.append("```\n")
        return "\n".join(lines)
