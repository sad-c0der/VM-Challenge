#!/usr/bin/python3
import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp
from miasm.ir.symbexec import SymbolicExecutionEngine


# Hardcode the VM Handlers
VM_HANDLERS = set([
    0x004011c5,
    0x00401404,
    0x00401310,
    0x00401589,
    0x0040145b,
    0x004014ad,
    0x00401375,
    0x0040155e,
    0x00401500,
    0x004013a8,
])

def constraint_memory(addr, nbytes):
    global container
    bstream = container.bin_stream.getbytes(addr, nbytes)
    sym_addr = ExprMem(ExprInt(addr, 64), nbytes * 8)
    sym_val = ExprInt(int.from_bytes(bstream, byteorder='little'), nbytes * 8)
    return sym_addr, sym_val

def disassemble(sb, addr):
    # Get VIP 
    vip = sb.symbols[ExprId("RAX", 64)]
    # Check addr for each handler
    if (int(addr) == 0x401331):
        address = expr_simp(vip + ExprInt(1, 64))
        value = expr_simp(sb.symbols[ExprMem(address, 64)])
        print(f"{vip}: handler: {addr} : value -> {value}")
    elif (int(addr) == 0x401404):
        address = expr_simp(sb.symbols[ExprId("RDX", 64)])
        value = sb.symbols[ExprMem(address, 32)]
        print(f"{vip}: CMPE: {value}")
    elif (int(addr) == 0x401310):
        address = expr_simp(sb.symbols[ExprId("RDX", 64)])
        value = expr_simp(sb.symbols[ExprMem(address, 64)])
        print(f"{vip}: VM_EXIT -> Return Value: {value}")
    elif (int(addr) == 0x401589):
        address = expr_simp(vip + ExprInt(4, 64))
        value = sb.symbols[ExprMem(address, 32)]
        print(f"{vip}: JE: {value}")
    elif (int(addr) == 0x40145b):
        print(f"{vip}: XOR")
    elif (int(addr) == 0x4014ad):
        address = expr_simp(sb.symbols[ExprId("RAX", 64)])
        value = sb.symbols[ExprMem(address, 64)]
        print(f"{vip}: PUSHLOCALVAR (Push Local Variable To Stack)")
    elif (int(addr) == 0x401375):
        address = expr_simp(sb.symbols[ExprId("RDX", 64)])
        value = expr_simp(sb.symbols[ExprMem(address, 64)])
        print(f"{vip}: PUSH: {value}")
    elif (int(addr) == 0x40155e):
        print(f"{vip}: PUSHFROMVAR (Load Integer From Local Variable And Push To Stack)")
    elif (int(addr) == 0x401500):
        address = expr_simp(sb.symbols[ExprId("RDI", 64)])
        value = expr_simp(sb.symbols[ExprMem(address, 64)])
        print(f"{vip}:  POPARGTOVAR {value}")
    elif (int(addr) == 0x4013a8):
        address = expr_simp((vip + ExprInt(1, 64)).signExtend(64))
        constant = sb.symbols[ExprMem(address, 32)]
        print(f"{vip}: POPTOVAR: (Assign Value To Local Variable)")
    else:
        print("Unknown VM Handler")


if len(sys.argv) != 2:
    print(f"[*] Syntax: {sys.argv[0]} <file>")
    exit()

# Path to our binary
file_path = sys.argv[1]

# Address of VM prolog
start_addr = 0x401236

# Initialize Symbol Table
loc_db = LocationDB()

# Read our binary file
container = Container.from_stream(open(file_path, 'rb'), loc_db)

# Get CPU Abstraction
machine = Machine(container.arch)

# Disassembly Engine
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)

# Initialize Lifter To Intermediate Representation
lifter = machine.lifter_model_call(mdis.loc_db)

# Disassemble Function At Given Address
asm_cfg = mdis.dis_multiblock(start_addr)

# Translate ASM CONF to IR CONF
ira_cfg = lifter.new_ircfg_from_asmcfg(asm_cfg)

# Initiate Symbolic Execution Engine
sb = SymbolicExecutionEngine(lifter)

# Constraint bytecode -- Start Address & Size (Highest Addr - Lowest Addr)
sym_addr, sym_val = constraint_memory(0x404060, 0x4040e0 - 0x404060)
sb.symbols[sym_addr] = sym_val

# constraint VM input (rdi, first function argument). The value in `ExprInt` rerpesents the function's input value.
rdi = ExprId("RDI", 64)
sb.symbols[rdi] = ExprInt(0xbadc1ed6edd6501e, 64)

# init worklist
basic_block_worklist = [ExprInt(start_addr, 64)]


# worklist algorithm
while basic_block_worklist:
    # get current block
    current_block = basic_block_worklist.pop()

    # if current block is a VM handler, dump handler-specific knowledge
    if current_block.is_int() and int(current_block) in VM_HANDLERS:
        disassemble(sb, current_block)

    # symbolical execute block -> next_block: symbolic value/address to execute
    next_block = sb.run_block_at(ira_cfg, current_block, step=False)

    # is next block is integer or label, continue execution
    if next_block.is_int() or next_block.is_loc():
        basic_block_worklist.append(next_block)

# dump symbolic state
# sb.dump()

# dump VMs/functions' return value -- only works if SE runs until the end
rax = ExprId("RAX", 64)
value = sb.symbols[rax]
print(f"VM return value: {value}")
