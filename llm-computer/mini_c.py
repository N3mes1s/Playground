"""
Mini-C Compiler: compiles a small C subset to WASM instructions.

This is the bridge that lets the transformer leverage arbitrary computation.
Instead of hand-writing WASM, programs are written in a readable C-like DSL
and compiled down to the VM's instruction set.

The blog says:
"We turn arbitrary C code into tokens that the model itself can execute
 reliably for millions of steps in seconds."

This compiler handles:
  - Variables (int), arrays (via memory)
  - Arithmetic, comparison, bitwise operators
  - if/else, while, for loops
  - Functions (non-recursive for now)
  - String/byte operations via memory
  - printf-style output

The compiler produces a flat list of WASM Instructions that the VM executes.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from wasm_vm import Op, Instruction


# ============================================================
# AST Nodes
# ============================================================

@dataclass
class IntLit:
    value: int

@dataclass
class Var:
    name: str

@dataclass
class BinOp:
    op: str  # +, -, *, /, %, ==, !=, <, >, <=, >=, &, |, ^, <<, >>
    left: object
    right: object

@dataclass
class UnaryOp:
    op: str  # !, -
    operand: object

@dataclass
class ArrayAccess:
    base: str   # variable name holding base address
    index: object  # expression for index

@dataclass
class ByteLoad:
    """Load a single byte from memory at address expr."""
    addr: object

@dataclass
class ByteStore:
    """Store a single byte to memory."""
    addr: object
    value: object

@dataclass
class WordLoad:
    """Load an i32 from memory at address expr."""
    addr: object

@dataclass
class WordStore:
    """Store an i32 to memory."""
    addr: object
    value: object

@dataclass
class Assign:
    name: str
    value: object

@dataclass
class If:
    cond: object
    then_body: list
    else_body: Optional[list] = None

@dataclass
class While:
    cond: object
    body: list

@dataclass
class For:
    init: object
    cond: object
    step: object
    body: list

@dataclass
class OutputInt:
    """Output an integer value to the trace."""
    value: object

@dataclass
class OutputChar:
    """Output a byte as a character."""
    value: object

@dataclass
class Break:
    pass

@dataclass
class Continue:
    pass

@dataclass
class Return:
    value: Optional[object] = None

@dataclass
class FuncCall:
    name: str
    args: list


# ============================================================
# Compiler
# ============================================================

class Compiler:
    """
    Compiles Mini-C AST to WASM instructions.

    Variable storage:
      - Locals 0-31 are available for scalar variables
      - Memory is used for arrays, strings, and heap data

    The compiler maintains a symbol table mapping variable names
    to local indices.
    """

    def __init__(self):
        self.locals_map: dict[str, int] = {}
        self.next_local: int = 0
        self.max_locals: int = 32
        self.code: list[Instruction] = []
        self._break_depth: list[int] = []  # control stack depth at each loop

    def compile(self, stmts: list) -> tuple[list[Instruction], int]:
        """
        Compile a list of statements into WASM instructions.
        Returns (instructions, n_locals_needed).
        """
        self.code = []
        self.locals_map = {}
        self.next_local = 0
        self._break_depth = []

        for stmt in stmts:
            self._compile_stmt(stmt)

        self.code.append(Instruction(Op.HALT))
        return self.code, max(self.next_local, 16)

    def _alloc_local(self, name: str) -> int:
        if name in self.locals_map:
            return self.locals_map[name]
        idx = self.next_local
        if idx >= self.max_locals:
            raise RuntimeError(f"Too many local variables (max {self.max_locals})")
        self.locals_map[name] = idx
        self.next_local += 1
        return idx

    def _get_local(self, name: str) -> int:
        if name not in self.locals_map:
            return self._alloc_local(name)
        return self.locals_map[name]

    # ---- Statements ----

    def _compile_stmt(self, stmt):
        if isinstance(stmt, Assign):
            self._compile_expr(stmt.value)
            idx = self._get_local(stmt.name)
            self.code.append(Instruction(Op.LOCAL_SET, idx))

        elif isinstance(stmt, If):
            self._compile_expr(stmt.cond)
            self.code.append(Instruction(Op.IF))
            for s in stmt.then_body:
                self._compile_stmt(s)
            if stmt.else_body:
                self.code.append(Instruction(Op.ELSE))
                for s in stmt.else_body:
                    self._compile_stmt(s)
            self.code.append(Instruction(Op.END))

        elif isinstance(stmt, While):
            # block { loop { br_if(!cond, 1); body; br 0; } }
            self.code.append(Instruction(Op.BLOCK))
            self.code.append(Instruction(Op.LOOP))
            self._break_depth.append(1)  # break = br 1 (exits block)

            # Evaluate condition; if false, break
            self._compile_expr(stmt.cond)
            self.code.append(Instruction(Op.I32_EQZ))
            self.code.append(Instruction(Op.BR_IF, 1))  # break

            for s in stmt.body:
                self._compile_stmt(s)

            self.code.append(Instruction(Op.BR, 0))  # continue
            self.code.append(Instruction(Op.END))  # end loop
            self.code.append(Instruction(Op.END))  # end block
            self._break_depth.pop()

        elif isinstance(stmt, For):
            # init; while(cond) { body; step; }
            self._compile_stmt(stmt.init)
            self._compile_stmt(While(stmt.cond, stmt.body + [stmt.step]))

        elif isinstance(stmt, OutputInt):
            self._compile_expr(stmt.value)
            self.code.append(Instruction(Op.OUTPUT))

        elif isinstance(stmt, OutputChar):
            self._compile_expr(stmt.value)
            self.code.append(Instruction(Op.OUTPUT_CHAR))

        elif isinstance(stmt, ByteStore):
            self._compile_expr(stmt.addr)
            self._compile_expr(stmt.value)
            self.code.append(Instruction(Op.I32_STORE8))

        elif isinstance(stmt, WordStore):
            self._compile_expr(stmt.addr)
            self._compile_expr(stmt.value)
            self.code.append(Instruction(Op.I32_STORE))

        elif isinstance(stmt, Break):
            if self._break_depth:
                self.code.append(Instruction(Op.BR, self._break_depth[-1]))

        elif isinstance(stmt, Continue):
            self.code.append(Instruction(Op.BR, 0))

        elif isinstance(stmt, Return):
            if stmt.value is not None:
                self._compile_expr(stmt.value)
                self.code.append(Instruction(Op.OUTPUT))
            self.code.append(Instruction(Op.HALT))

        else:
            raise ValueError(f"Unknown statement type: {type(stmt)}")

    # ---- Expressions ----

    def _compile_expr(self, expr):
        if isinstance(expr, IntLit):
            self.code.append(Instruction(Op.I32_CONST, expr.value))

        elif isinstance(expr, Var):
            idx = self._get_local(expr.name)
            self.code.append(Instruction(Op.LOCAL_GET, idx))

        elif isinstance(expr, BinOp):
            if expr.op in ('/', '%'):
                # Decompose DIV/REM into repeated subtraction loop
                # This avoids i32.div_s and i32.rem_s which can't be computed natively
                # Result: a / b (quotient) or a % b (remainder) using only SUB/ADD/GE_S
                self._compile_expr(expr.left)   # push a
                self._compile_expr(expr.right)  # push b
                # Store in temp locals
                div_b = self._get_local('__div_b')
                div_a = self._get_local('__div_a')
                div_q = self._get_local('__div_q')
                self.code.append(Instruction(Op.LOCAL_SET, div_b))  # b
                self.code.append(Instruction(Op.LOCAL_SET, div_a))  # a
                self.code.append(Instruction(Op.I32_CONST, 0))
                self.code.append(Instruction(Op.LOCAL_SET, div_q))  # q = 0
                # while a >= b: a -= b; q += 1
                self.code.append(Instruction(Op.BLOCK))
                self.code.append(Instruction(Op.LOOP))
                # condition: a >= b
                self.code.append(Instruction(Op.LOCAL_GET, div_a))
                self.code.append(Instruction(Op.LOCAL_GET, div_b))
                self.code.append(Instruction(Op.I32_GE_S))
                self.code.append(Instruction(Op.I32_EQZ))
                self.code.append(Instruction(Op.BR_IF, 1))  # break if NOT (a >= b)
                # a -= b
                self.code.append(Instruction(Op.LOCAL_GET, div_a))
                self.code.append(Instruction(Op.LOCAL_GET, div_b))
                self.code.append(Instruction(Op.I32_SUB))
                self.code.append(Instruction(Op.LOCAL_SET, div_a))
                # q += 1
                self.code.append(Instruction(Op.LOCAL_GET, div_q))
                self.code.append(Instruction(Op.I32_CONST, 1))
                self.code.append(Instruction(Op.I32_ADD))
                self.code.append(Instruction(Op.LOCAL_SET, div_q))
                # continue loop
                self.code.append(Instruction(Op.BR, 0))
                self.code.append(Instruction(Op.END))  # end loop
                self.code.append(Instruction(Op.END))  # end block
                # Push result: quotient for /, remainder for %
                if expr.op == '/':
                    self.code.append(Instruction(Op.LOCAL_GET, div_q))
                else:
                    self.code.append(Instruction(Op.LOCAL_GET, div_a))
            else:
                self._compile_expr(expr.left)
                self._compile_expr(expr.right)
                op_map = {
                    '+': Op.I32_ADD, '-': Op.I32_SUB,
                    '*': Op.I32_MUL,
                    '==': Op.I32_EQ, '!=': Op.I32_NE,
                    '<': Op.I32_LT_S, '>': Op.I32_GT_S,
                    '<=': Op.I32_LE_S, '>=': Op.I32_GE_S,
                    '&': Op.I32_AND, '|': Op.I32_OR, '^': Op.I32_XOR,
                    '<<': Op.I32_SHL, '>>': Op.I32_SHR_S,
                }
                if expr.op not in op_map:
                    raise ValueError(f"Unknown binary op: {expr.op}")
                self.code.append(Instruction(op_map[expr.op]))

        elif isinstance(expr, UnaryOp):
            if expr.op == '-':
                self.code.append(Instruction(Op.I32_CONST, 0))
                self._compile_expr(expr.operand)
                self.code.append(Instruction(Op.I32_SUB))
            elif expr.op == '!':
                self._compile_expr(expr.operand)
                self.code.append(Instruction(Op.I32_EQZ))

        elif isinstance(expr, ByteLoad):
            self._compile_expr(expr.addr)
            self.code.append(Instruction(Op.I32_LOAD8_U))

        elif isinstance(expr, WordLoad):
            self._compile_expr(expr.addr)
            self.code.append(Instruction(Op.I32_LOAD))

        elif isinstance(expr, ArrayAccess):
            # base_addr + index * element_size
            idx = self._get_local(expr.base)
            self.code.append(Instruction(Op.LOCAL_GET, idx))
            self._compile_expr(expr.index)
            self.code.append(Instruction(Op.I32_ADD))
            self.code.append(Instruction(Op.I32_LOAD8_U))

        elif isinstance(expr, FuncCall):
            # Built-in function calls compiled inline
            if expr.name == 'input_size':
                self.code.append(Instruction(Op.INPUT_SIZE))
            else:
                raise ValueError(f"Unknown function: {expr.name}")

        else:
            raise ValueError(f"Unknown expression type: {type(expr)}")


# ============================================================
# Program builder helpers (fluent API)
# ============================================================

def var(name: str) -> Var:
    return Var(name)

def lit(value: int) -> IntLit:
    return IntLit(value)

def add(a, b) -> BinOp:
    return BinOp('+', a, b)

def sub(a, b) -> BinOp:
    return BinOp('-', a, b)

def mul(a, b) -> BinOp:
    return BinOp('*', a, b)

def div(a, b) -> BinOp:
    return BinOp('/', a, b)

def mod(a, b) -> BinOp:
    return BinOp('%', a, b)

def eq(a, b) -> BinOp:
    return BinOp('==', a, b)

def ne(a, b) -> BinOp:
    return BinOp('!=', a, b)

def lt(a, b) -> BinOp:
    return BinOp('<', a, b)

def gt(a, b) -> BinOp:
    return BinOp('>', a, b)

def le(a, b) -> BinOp:
    return BinOp('<=', a, b)

def ge(a, b) -> BinOp:
    return BinOp('>=', a, b)

def band(a, b) -> BinOp:
    return BinOp('&', a, b)

def bor(a, b) -> BinOp:
    return BinOp('|', a, b)

def byte_at(addr) -> ByteLoad:
    return ByteLoad(addr)

def assign(name: str, value) -> Assign:
    return Assign(name, value)

def output_int(value) -> OutputInt:
    return OutputInt(value)

def output_char(value) -> OutputChar:
    return OutputChar(value)

def store_byte(addr, value) -> ByteStore:
    return ByteStore(addr, value)

def store_word(addr, value) -> WordStore:
    return WordStore(addr, value)

def if_then(cond, then_body, else_body=None) -> If:
    return If(cond, then_body, else_body)

def while_loop(cond, body) -> While:
    return While(cond, body)

def for_loop(init, cond, step, body) -> For:
    return For(init, cond, step, body)
