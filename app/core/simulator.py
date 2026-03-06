"""
Lightweight RISC-V simulator for execution tracing and benchmarking.
Supports instruction execution, I/O simulation, memory region tracking, and loop profiling.
"""

import struct
import io
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict


class MemoryRegion:
    """Track a memory region (stack, heap, code, data)."""
    def __init__(self, start: int, size: int, region_type: str):
        self.start = start
        self.size = size
        self.region_type = region_type  # 'stack', 'heap', 'code', 'data'
        self.high_watermark = start
        self.access_count = 0
    
    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.start + self.size
    
    def record_access(self, addr: int):
        self.access_count += 1
        if addr > self.high_watermark:
            self.high_watermark = addr


class RiscVSimulator:
    """Enhanced RISC-V 64-bit simulator with I/O, loop profiling, and memory analysis."""
    
    def __init__(self, memory_size: int = 1024 * 1024):
        """Initialize simulator with register file and memory."""
        self.registers = [0] * 32  # x0-x31 (x0 always 0)
        self.memory = bytearray(memory_size)
        self.pc = 0  # Program counter
        self.instructions_executed = 0
        self.instruction_counts: Dict[str, int] = {}
        self.memory_accesses = []  # Track loads/stores
        self.register_writes: Dict[int, int] = {}  # Track which registers written
        self.cycles_estimate = 0
        self.branching_history = []
        self.output_buffer = io.StringIO()
        self.input_buffer = ""
        self.input_pos = 0
        
        # I/O tracking
        self.io_operations = []  # Track putchar, getchar, write syscalls
        
        # Memory regions
        self.memory_regions = {
            'stack': MemoryRegion(memory_size - 65536, 65536, 'stack'),  # 64KB stack at top
            'heap': MemoryRegion(4096, memory_size // 4, 'heap'),  # Heap at 4KB
            'code': MemoryRegion(0x1000, 65536, 'code'),  # Code section
        }
        
        # Loop profiling
        self.loop_map = {}  # Maps back-edge addresses to loop info
        self.loop_iterations = defaultdict(int)  # Count iterations per loop
        self.pc_history = []  # Track PC for loop detection
        
    def set_registers_from_abi(self, a0: int = 0, a1: int = 0, a2: int = 0, a3: int = 0):
        """Set up argument registers for function testing (x10-x13)."""
        self.registers[10] = a0
        self.registers[11] = a1
        self.registers[12] = a2
        self.registers[13] = a3
    
    def load_memory(self, address: int, data: bytes):
        """Load binary data into memory at address."""
        if address + len(data) <= len(self.memory):
            self.memory[address:address + len(data)] = data
    
    def set_input(self, input_str: str):
        """Set stdin for the simulated program."""
        self.input_buffer = input_str
        self.input_pos = 0
    
    def get_output(self) -> str:
        """Get captured stdout."""
        return self.output_buffer.getvalue()
    
    def read_register(self, reg: int) -> int:
        """Read register value (x0 always returns 0)."""
        if reg == 0:
            return 0
        return self.registers[reg] & ((1 << 64) - 1)  # Mask to 64-bit
    
    def write_register(self, reg: int, value: int):
        """Write register value (x0 writes ignored)."""
        if reg == 0:
            return
        self.registers[reg] = value & ((1 << 64) - 1)  # Mask to 64-bit
        self.register_writes[reg] = self.register_writes.get(reg, 0) + 1
    
    def read_memory(self, address: int, size: int) -> int:
        """Read from memory (little-endian)."""
        try:
            data = self.memory[address:address + size]
            if len(data) < size:
                return 0
            # Record access in memory region
            for region in self.memory_regions.values():
                if region.contains(address):
                    region.record_access(address)
            return int.from_bytes(data, byteorder='little')
        except:
            return 0
    
    def write_memory(self, address: int, value: int, size: int):
        """Write to memory (little-endian)."""
        try:
            data = value.to_bytes(size, byteorder='little')
            self.memory[address:address + size] = data
            
            # Record access in memory region
            region_type = 'data'
            for region in self.memory_regions.values():
                if region.contains(address):
                    region.record_access(address)
                    region_type = region.region_type
            
            self.memory_accesses.append({
                "type": "store",
                "address": address,
                "size": size,
                "value": value,
                "region": region_type
            })
        except:
            pass
    
    def detect_loop_back_edge(self, from_addr: int, to_addr: int):
        """Detect if this branch creates a loop back-edge."""
        if to_addr < from_addr:  # Back-edge heuristic
            loop_key = f"{to_addr:x}"
            if loop_key not in self.loop_map:
                self.loop_map[loop_key] = {
                    "entry": to_addr,
                    "exit": from_addr,
                    "iterations": 0
                }
            self.loop_iterations[loop_key] += 1
    
    def simulate_syscall(self, a7: int) -> int:
        """Simulate RISC-V syscalls (a7 = syscall number)."""
        syscall_names = {
            64: 'write',
            63: 'read',
            93: 'exit',
            214: 'brk',  # Heap management
        }
        
        syscall_name = syscall_names.get(a7, f'unknown({a7})')
        
        # a0, a1, a2 are first three arguments
        a0 = self.read_register(10)
        a1 = self.read_register(11)
        a2 = self.read_register(12)
        
        if a7 == 64:  # write(fd, buf, count)
            # fd=a0, buf=a1, count=a2
            try:
                data = self.memory[a1:a1 + a2]
                self.output_buffer.write(data.decode('utf-8', errors='ignore'))
                self.io_operations.append({
                    "type": "write",
                    "fd": a0,
                    "count": a2,
                    "data": data[:20].decode('utf-8', errors='ignore')  # First 20 bytes
                })
                return a2
            except:
                pass
        
        elif a7 == 63:  # read(fd, buf, count)
            if self.input_pos < len(self.input_buffer):
                read_size = min(a2, len(self.input_buffer) - self.input_pos)
                data = self.input_buffer[self.input_pos:self.input_pos + read_size].encode()
                self.write_memory(a1, int.from_bytes(data, 'little'), read_size)
                self.input_pos += read_size
                self.io_operations.append({
                    "type": "read",
                    "fd": a0,
                    "count": read_size
                })
                return read_size
        
        elif a7 == 93:  # exit
            return 0  # Signal exit
        
        return 0

    def run(self, instructions: List[Dict[str, Any]], max_iterations: int = 10000) -> Dict[str, Any]:
        """
        Run simulation on instruction list.
        Returns execution statistics including I/O, memory regions, and loops.
        """
        iteration = 0
        for instr in instructions:
            if iteration >= max_iterations:
                break
            if not self.execute_instruction(instr):
                break
            iteration += 1
        
        # Compile loop profiling data
        loop_profiles = []
        for loop_key, loop_info in self.loop_map.items():
            loop_profiles.append({
                "entry": f"0x{loop_info['entry']:x}",
                "exit": f"0x{loop_info['exit']:x}",
                "iterations": self.loop_iterations.get(loop_key, 0)
            })
        
        # Memory region summary
        region_summary = {}
        for name, region in self.memory_regions.items():
            region_summary[name] = {
                "start": region.start,
                "size": region.size,
                "high_watermark": region.high_watermark,
                "utilization": f"{(region.high_watermark - region.start) / region.size * 100:.1f}%",
                "access_count": region.access_count
            }
        
        # Compile statistics
        stats = {
            "instructions_executed": self.instructions_executed,
            "cycles_estimate": self.cycles_estimate,
            "ipc_estimate": self.instructions_executed / max(1, self.cycles_estimate),
            "instruction_mix": self.instruction_counts,
            "register_writes": self.register_writes,
            "memory_accesses": {
                "total": len(self.memory_accesses),
                "loads": len([a for a in self.memory_accesses if a["type"] == "load"]),
                "stores": len([a for a in self.memory_accesses if a["type"] == "store"]),
                "access_log": self.memory_accesses[:50]  # First 50 for UI
            },
            "branches_taken": len([b for b in self.branching_history if b["taken"]]),
            "branches_total": len(self.branching_history),
            "io_operations": self.io_operations,
            "output": self.get_output()[:500],  # Limit output
            "unique_registers_written": len(self.register_writes),
            "final_register_state": {f"x{i}": self.read_register(i) for i in range(32) if self.register_writes.get(i, 0) > 0},
            "loops_detected": loop_profiles,
            "memory_regions": region_summary,
            "stack_usage": f"{region_summary.get('stack', {}).get('utilization', 'N/A')}",
            "heap_usage": f"{region_summary.get('heap', {}).get('utilization', 'N/A')}"
        }
        
        return stats
    
    def execute_instruction(self, instr: Dict[str, Any]) -> bool:
        """
        Execute a single instruction from disassembly dict.
        Returns False if execution should stop, True to continue.
        """
        mnemonic = (instr.get("mnemonic") or "").lower()
        op_str = instr.get("op_str") or instr.get("opstr") or ""
        
        # Track instruction
        self.instructions_executed += 1
        self.instruction_counts[mnemonic] = self.instruction_counts.get(mnemonic, 0) + 1
        self.cycles_estimate += self._estimate_cycles(mnemonic)
        
        try:
            # Parse operands
            ops = [p.strip() for p in op_str.split(',')] if op_str else []
            
            # Helper: convert ABI register name to number
            def get_register_number(reg_str):
                """Convert register name (x0, a0, s0, etc.) to register number."""
                reg_str = reg_str.strip()
                # ABI name mappings
                abi_map = {
                    'zero': 0, 'ra': 1, 'sp': 2, 'gp': 3, 'tp': 4,
                    't0': 5, 't1': 6, 't2': 7,
                    's0': 8, 'fp': 8, 's1': 9,
                    'a0': 10, 'a1': 11, 'a2': 12, 'a3': 13, 'a4': 14, 'a5': 15, 'a6': 16, 'a7': 17,
                    's2': 18, 's3': 19, 's4': 20, 's5': 21, 's6': 22, 's7': 23, 's8': 24, 's9': 25, 's10': 26, 's11': 27,
                    't3': 28, 't4': 29, 't5': 30, 't6': 31
                }
                if reg_str in abi_map:
                    return abi_map[reg_str]
                elif reg_str.startswith('x'):
                    try:
                        return int(reg_str[1:])
                    except:
                        return 0
                else:
                    return 0
            
            # Helper: parse operand (register or immediate)
            def parse_operand(op):
                op = op.strip()
                # Check if register (x-format or ABI name)
                if op.startswith('x') or op in {'zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2', 's0', 'fp', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6'}:
                    reg_num = get_register_number(op)
                    return ('reg', reg_num)
                # Immediate or offset(base) format
                elif '(' in op and ')' in op:
                    # offset(base) format like -0x28(s0) or 0x10(x2)
                    parts = op.split('(')
                    offset_str = parts[0].strip()
                    base_str = parts[1].rstrip(')')
                    
                    # Parse offset (handle negative hex like -0x28)
                    try:
                        offset = int(offset_str, 0) if offset_str else 0
                    except:
                        offset = 0
                    
                    # Parse base register
                    base_reg = get_register_number(base_str.strip())
                    return ('offset', offset, base_reg)
                else:
                    # Simple immediate (handle negative hex like -0x1fc)
                    try:
                        return ('imm', int(op, 0))
                    except:
                        return ('imm', 0)
            
            # Execute by mnemonic category
            if mnemonic in {'addi', 'addw', 'subi'}:
                # addi rd, rs, imm
                if len(ops) >= 3:
                    rd = get_register_number(ops[0])
                    rs = parse_operand(ops[1])
                    imm = parse_operand(ops[2])
                    rs_val = self.read_register(rs[1]) if rs[0] == 'reg' else 0
                    imm_val = imm[1] if imm[0] == 'imm' else 0
                    result = rs_val + imm_val
                    self.write_register(rd, result)
            
            elif mnemonic in {'add', 'sub', 'mul', 'div'}:
                # arith rd, rs1, rs2
                if len(ops) >= 3:
                    rd = get_register_number(ops[0])
                    rs1 = parse_operand(ops[1])
                    rs2 = parse_operand(ops[2])
                    rs1_val = self.read_register(rs1[1]) if rs1[0] == 'reg' else 0
                    rs2_val = self.read_register(rs2[1]) if rs2[0] == 'reg' else 0
                    
                    if mnemonic == 'add':
                        result = rs1_val + rs2_val
                    elif mnemonic == 'sub':
                        result = rs1_val - rs2_val
                    elif mnemonic == 'mul':
                        result = rs1_val * rs2_val
                    elif mnemonic == 'div':
                        result = rs1_val // rs2_val if rs2_val != 0 else 0
                    else:
                        result = 0
                    self.write_register(rd, result)
            
            elif mnemonic in {'lw', 'ld', 'lb', 'lh'}:
                # load rd, offset(base)
                if len(ops) >= 2:
                    rd = get_register_number(ops[0])
                    addr_info = parse_operand(ops[1])
                    if addr_info[0] == 'offset':
                        base_val = self.read_register(addr_info[2])
                        address = base_val + addr_info[1]
                        size = {'lw': 4, 'ld': 8, 'lb': 1, 'lh': 2}.get(mnemonic, 4)
                        value = self.read_memory(address, size)
                        self.memory_accesses.append({
                            "type": "load",
                            "address": address,
                            "size": size,
                            "value": value
                        })
                        self.write_register(rd, value)
            
            elif mnemonic in {'sw', 'sd', 'sb', 'sh'}:
                # store rs, offset(base)
                if len(ops) >= 2:
                    rs = parse_operand(ops[0])
                    addr_info = parse_operand(ops[1])
                    if addr_info[0] == 'offset':
                        rs_val = self.read_register(rs[1]) if rs[0] == 'reg' else 0
                        base_val = self.read_register(addr_info[2])
                        address = base_val + addr_info[1]
                        size = {'sw': 4, 'sd': 8, 'sb': 1, 'sh': 2}.get(mnemonic, 4)
                        self.write_memory(address, rs_val, size)
            
            elif mnemonic in {'beq', 'bne', 'blt', 'bge'}:
                # branch rs1, rs2, target
                if len(ops) >= 3:
                    rs1 = parse_operand(ops[0])
                    rs2 = parse_operand(ops[1])
                    rs1_val = self.read_register(rs1[1]) if rs1[0] == 'reg' else 0
                    rs2_val = self.read_register(rs2[1]) if rs2[0] == 'reg' else 0
                    
                    branch_taken = False
                    if mnemonic == 'beq':
                        branch_taken = rs1_val == rs2_val
                    elif mnemonic == 'bne':
                        branch_taken = rs1_val != rs2_val
                    elif mnemonic == 'blt':
                        branch_taken = rs1_val < rs2_val
                    elif mnemonic == 'bge':
                        branch_taken = rs1_val >= rs2_val
                    
                    self.branching_history.append({
                        "instruction": mnemonic,
                        "taken": branch_taken
                    })
            
            elif mnemonic in {'jal', 'jalr'}:
                # Jump: typically ends function or calls
                if len(ops) > 0:
                    rd = get_register_number(ops[0])
                    # Store return address (PC + 4 or 8 depending on compressed)
                    self.write_register(rd, self.pc + 4)
        
        except Exception as e:
            print(f"Execution error in {mnemonic}: {e}")
            return True  # Continue despite error
        
        return True  # Continue execution
    
    def _estimate_cycles(self, mnemonic: str) -> int:
        """Estimate cycle cost for instruction type."""
        cycles_map = {
            'add': 1, 'sub': 1, 'addi': 1, 'subi': 1,
            'mul': 3, 'div': 20,
            'lw': 3, 'ld': 3, 'lb': 3, 'lh': 3,
            'sw': 1, 'sd': 1, 'sb': 1, 'sh': 1,
            'beq': 1, 'bne': 1, 'blt': 1, 'bge': 1,
            'jal': 1, 'jalr': 1,
        }
        return cycles_map.get(mnemonic, 1)
    
    def run(self, instructions: List[Dict[str, Any]], max_iterations: int = 10000) -> Dict[str, Any]:
        """
        Run simulation on instruction list.
        Returns execution statistics.
        """
        iteration = 0
        for instr in instructions:
            if iteration >= max_iterations:
                break
            if not self.execute_instruction(instr):
                break
            iteration += 1
        
        # Compile statistics
        stats = {
            "instructions_executed": self.instructions_executed,
            "cycles_estimate": self.cycles_estimate,
            "ipc_estimate": self.instructions_executed / max(1, self.cycles_estimate),
            "instruction_mix": self.instruction_counts,
            "register_writes": self.register_writes,
            "memory_accesses": {
                "total": len(self.memory_accesses),
                "loads": len([a for a in self.memory_accesses if a["type"] == "load"]),
                "stores": len([a for a in self.memory_accesses if a["type"] == "store"]),
                "access_log": self.memory_accesses[:50]  # First 50 for UI
            },
            "branches_taken": len([b for b in self.branching_history if b["taken"]]),
            "branches_total": len(self.branching_history),
            "output": self.get_output(),
            "unique_registers_written": len(self.register_writes),
            "final_register_state": {f"x{i}": self.read_register(i) for i in range(32) if self.register_writes.get(i, 0) > 0}
        }
        print(stats)
        return stats
