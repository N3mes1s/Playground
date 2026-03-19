"""
Training pipeline for the WASM-in-transformer interpreter.

Generates random WASM programs, computes ground-truth traces via the VM,
and trains the model using teacher forcing with cross-entropy loss on
trace token positions only.

Usage:
    uv run --with torch --with numpy python train.py
"""

import random
import struct
import time
from dataclasses import dataclass

import torch
import torch.nn as nn
import torch.nn.functional as F

from wasm_vm import Instruction, Op, WasmVM
from compiler import TraceVocab
from autoregressive_interpreter import (
    build_native_interpreter,
    encode_program_native,
    encode_program_hybrid,
    generate_trace,
    generate_trace_rust_multilayer,
    run_native,
    D_MODEL, N_HEADS, N_LAYERS, D_FFN, MAX_SEQ,
    PROG_LEN, SEP_POS, TRACE_START, STEP_SIZE,
    COMMIT_OUTPUT, COMMIT_HALT, INST_SIZE,
    _set_universal_pe, _set_ip_pe,
)


# ============================================================
# 1. Program Generator
# ============================================================

def _rand_small_int(lo=-100, hi=100):
    """Random small integer for operands."""
    return random.randint(lo, hi)


def _rand_positive_int(lo=1, hi=50):
    """Random positive integer (for divisors, shift amounts, etc.)."""
    return random.randint(lo, hi)


def gen_arithmetic_program() -> list[Instruction]:
    """
    Generate: a OP b -> output, halt
    OP in {+, -, *, /, %, &, |, ^, <<, >>}
    Uses NATIVE WASM ops (i32.div_s, i32.rem_s, i32.and, etc.)
    """
    a = _rand_small_int()
    b = _rand_small_int()
    op_choice = random.choice([
        'add', 'sub', 'mul', 'div', 'rem',
        'and', 'or', 'xor', 'shl', 'shr',
    ])

    # Ensure safe operands
    if op_choice in ('div', 'rem'):
        b = _rand_positive_int(1, 30)  # avoid div by zero
        a = abs(a) if random.random() < 0.7 else a  # mostly positive for simplicity
    elif op_choice in ('shl', 'shr'):
        a = random.randint(0, 255)
        b = random.randint(0, 8)
    elif op_choice in ('and', 'or', 'xor'):
        a = random.randint(0, 255)
        b = random.randint(0, 255)

    op_map = {
        'add': Op.I32_ADD, 'sub': Op.I32_SUB, 'mul': Op.I32_MUL,
        'div': Op.I32_DIV_S, 'rem': Op.I32_REM_S,
        'and': Op.I32_AND, 'or': Op.I32_OR, 'xor': Op.I32_XOR,
        'shl': Op.I32_SHL, 'shr': Op.I32_SHR_S,
    }

    return [
        Instruction(Op.I32_CONST, a),
        Instruction(Op.I32_CONST, b),
        Instruction(op_map[op_choice]),
        Instruction(Op.OUTPUT),
        Instruction(Op.HALT),
    ]


def gen_comparison_program() -> list[Instruction]:
    """
    Generate: a CMP b -> output, halt
    CMP in {<, >, <=, >=, ==, !=}
    """
    a = _rand_small_int()
    b = _rand_small_int()
    # Sometimes make them equal for == tests
    if random.random() < 0.2:
        b = a

    cmp_map = {
        'lt': Op.I32_LT_S, 'gt': Op.I32_GT_S,
        'le': Op.I32_LE_S, 'ge': Op.I32_GE_S,
        'eq': Op.I32_EQ, 'ne': Op.I32_NE,
    }
    cmp_choice = random.choice(list(cmp_map.keys()))

    return [
        Instruction(Op.I32_CONST, a),
        Instruction(Op.I32_CONST, b),
        Instruction(cmp_map[cmp_choice]),
        Instruction(Op.OUTPUT),
        Instruction(Op.HALT),
    ]


def gen_local_variable_program() -> list[Instruction]:
    """
    Generate programs that use local.set/get/tee with arithmetic.
    Example: x = a; y = b; output x + y
    """
    a = _rand_small_int(-50, 50)
    b = _rand_small_int(-50, 50)
    op_choice = random.choice(['add', 'sub', 'mul'])
    op_map = {'add': Op.I32_ADD, 'sub': Op.I32_SUB, 'mul': Op.I32_MUL}

    variant = random.randint(0, 2)
    if variant == 0:
        # x = a; y = b; output x OP y
        return [
            Instruction(Op.I32_CONST, a),
            Instruction(Op.LOCAL_SET, 0),
            Instruction(Op.I32_CONST, b),
            Instruction(Op.LOCAL_SET, 1),
            Instruction(Op.LOCAL_GET, 0),
            Instruction(Op.LOCAL_GET, 1),
            Instruction(op_map[op_choice]),
            Instruction(Op.OUTPUT),
            Instruction(Op.HALT),
        ]
    elif variant == 1:
        # x = a; x = x OP b; output x
        return [
            Instruction(Op.I32_CONST, a),
            Instruction(Op.LOCAL_SET, 0),
            Instruction(Op.LOCAL_GET, 0),
            Instruction(Op.I32_CONST, b),
            Instruction(op_map[op_choice]),
            Instruction(Op.LOCAL_SET, 0),
            Instruction(Op.LOCAL_GET, 0),
            Instruction(Op.OUTPUT),
            Instruction(Op.HALT),
        ]
    else:
        # Use local.tee: push a, tee to local 0, push b, OP, output
        return [
            Instruction(Op.I32_CONST, a),
            Instruction(Op.LOCAL_TEE, 0),
            Instruction(Op.I32_CONST, b),
            Instruction(op_map[op_choice]),
            Instruction(Op.OUTPUT),
            Instruction(Op.HALT),
        ]


def gen_if_else_program() -> list[Instruction]:
    """
    Generate: if (a CMP b) { output c } else { output d }; halt
    """
    a = _rand_small_int(-20, 20)
    b = _rand_small_int(-20, 20)
    c = _rand_small_int(0, 50)
    d = _rand_small_int(0, 50)

    cmp_map = {
        'lt': Op.I32_LT_S, 'gt': Op.I32_GT_S,
        'le': Op.I32_LE_S, 'ge': Op.I32_GE_S,
        'eq': Op.I32_EQ, 'ne': Op.I32_NE,
    }
    cmp_choice = random.choice(list(cmp_map.keys()))

    return [
        Instruction(Op.I32_CONST, a),
        Instruction(Op.I32_CONST, b),
        Instruction(cmp_map[cmp_choice]),
        Instruction(Op.IF),
        Instruction(Op.I32_CONST, c),
        Instruction(Op.OUTPUT),
        Instruction(Op.ELSE),
        Instruction(Op.I32_CONST, d),
        Instruction(Op.OUTPUT),
        Instruction(Op.END),
        Instruction(Op.HALT),
    ]


def gen_while_loop_program() -> list[Instruction]:
    """
    Generate: sum = 0; i = 1; while (i <= n) { sum += i; i += 1 }; output sum
    With small n (2-6) to keep traces short.
    """
    n = random.randint(2, 6)
    return [
        # sum = 0  (local 0)
        Instruction(Op.I32_CONST, 0),
        Instruction(Op.LOCAL_SET, 0),
        # i = 1  (local 1)
        Instruction(Op.I32_CONST, 1),
        Instruction(Op.LOCAL_SET, 1),
        # block { loop {
        Instruction(Op.BLOCK),
        Instruction(Op.LOOP),
        # if (i > n) break
        Instruction(Op.LOCAL_GET, 1),
        Instruction(Op.I32_CONST, n),
        Instruction(Op.I32_GT_S),
        Instruction(Op.BR_IF, 1),
        # sum += i
        Instruction(Op.LOCAL_GET, 0),
        Instruction(Op.LOCAL_GET, 1),
        Instruction(Op.I32_ADD),
        Instruction(Op.LOCAL_SET, 0),
        # i += 1
        Instruction(Op.LOCAL_GET, 1),
        Instruction(Op.I32_CONST, 1),
        Instruction(Op.I32_ADD),
        Instruction(Op.LOCAL_SET, 1),
        # continue
        Instruction(Op.BR, 0),
        Instruction(Op.END),  # end loop
        Instruction(Op.END),  # end block
        # output sum
        Instruction(Op.LOCAL_GET, 0),
        Instruction(Op.OUTPUT),
        Instruction(Op.HALT),
    ]


def gen_mixed_program() -> list[Instruction]:
    """
    Generate mixed programs: arithmetic + locals + simple control flow.
    Example: x = a OP b; if (x CMP c) { output x } else { output 0 }
    """
    a = _rand_small_int(-20, 20)
    b = _rand_small_int(-20, 20)
    c = _rand_small_int(-20, 20)

    arith_ops = [Op.I32_ADD, Op.I32_SUB, Op.I32_MUL]
    arith_op = random.choice(arith_ops)
    cmp_ops = [Op.I32_LT_S, Op.I32_GT_S, Op.I32_LE_S, Op.I32_GE_S, Op.I32_EQ, Op.I32_NE]
    cmp_op = random.choice(cmp_ops)

    return [
        # x = a OP b
        Instruction(Op.I32_CONST, a),
        Instruction(Op.I32_CONST, b),
        Instruction(arith_op),
        Instruction(Op.LOCAL_SET, 0),
        # if (x CMP c) { output x } else { output 0 }
        Instruction(Op.LOCAL_GET, 0),
        Instruction(Op.I32_CONST, c),
        Instruction(cmp_op),
        Instruction(Op.IF),
        Instruction(Op.LOCAL_GET, 0),
        Instruction(Op.OUTPUT),
        Instruction(Op.ELSE),
        Instruction(Op.I32_CONST, 0),
        Instruction(Op.OUTPUT),
        Instruction(Op.END),
        Instruction(Op.HALT),
    ]


def gen_chained_arithmetic_program() -> list[Instruction]:
    """
    Generate chained arithmetic: a OP1 b OP2 c -> output
    """
    a = _rand_small_int(-30, 30)
    b = _rand_small_int(-30, 30)
    c = _rand_small_int(-30, 30)
    ops = [Op.I32_ADD, Op.I32_SUB, Op.I32_MUL]
    op1 = random.choice(ops)
    op2 = random.choice(ops)

    return [
        Instruction(Op.I32_CONST, a),
        Instruction(Op.I32_CONST, b),
        Instruction(op1),
        Instruction(Op.I32_CONST, c),
        Instruction(op2),
        Instruction(Op.OUTPUT),
        Instruction(Op.HALT),
    ]


def gen_eqz_program() -> list[Instruction]:
    """Generate: eqz(a) -> output"""
    a = random.choice([0, 0, 0, _rand_small_int()])
    return [
        Instruction(Op.I32_CONST, a),
        Instruction(Op.I32_EQZ),
        Instruction(Op.OUTPUT),
        Instruction(Op.HALT),
    ]


def gen_native_bitwise_program() -> list[Instruction]:
    """
    Generate native bitwise/div/rem programs for training.
    Uses the actual WASM opcodes (not compiler decomposition).
    """
    a = random.randint(0, 255)
    b = random.randint(0, 255)
    op_choice = random.choice(['div', 'rem', 'and', 'or', 'xor', 'shl', 'shr'])

    if op_choice in ('div', 'rem'):
        a = random.randint(1, 200)
        b = random.randint(1, 30)
    elif op_choice in ('shl', 'shr'):
        a = random.randint(0, 255)
        b = random.randint(0, 8)

    op_map = {
        'div': Op.I32_DIV_S, 'rem': Op.I32_REM_S,
        'and': Op.I32_AND, 'or': Op.I32_OR, 'xor': Op.I32_XOR,
        'shl': Op.I32_SHL, 'shr': Op.I32_SHR_S,
    }

    return [
        Instruction(Op.I32_CONST, a),
        Instruction(Op.I32_CONST, b),
        Instruction(op_map[op_choice]),
        Instruction(Op.OUTPUT),
        Instruction(Op.HALT),
    ]


# Distribution of program generators
PROGRAM_GENERATORS = [
    (gen_arithmetic_program, 0.20),
    (gen_comparison_program, 0.10),
    (gen_local_variable_program, 0.15),
    (gen_if_else_program, 0.10),
    (gen_while_loop_program, 0.10),
    (gen_mixed_program, 0.10),
    (gen_chained_arithmetic_program, 0.05),
    (gen_eqz_program, 0.05),
    (gen_native_bitwise_program, 0.15),
]


def generate_random_program() -> list[Instruction]:
    """Sample a random program from the generator distribution."""
    r = random.random()
    cumulative = 0.0
    for gen_fn, prob in PROGRAM_GENERATORS:
        cumulative += prob
        if r < cumulative:
            return gen_fn()
    return PROGRAM_GENERATORS[0][0]()


# ============================================================
# 2. Trace Data Generation
# ============================================================

def has_control_flow(program: list[Instruction]) -> bool:
    """Check if program has control flow or local variable ops."""
    return any(
        inst.op in (Op.IF, Op.ELSE, Op.BLOCK, Op.LOOP, Op.BR, Op.BR_IF,
                    Op.LOCAL_GET, Op.LOCAL_SET, Op.LOCAL_TEE)
        for inst in program
    )


def build_vm_expected_trace(program: list[Instruction]) -> list[int]:
    """
    Run program through VM and build the expected trace tokens.
    This is the ground truth for training.

    Returns a flat list of trace tokens: [b0, b1, b2, b3, commit] per step.
    For OUTPUT: [0, 0, 0, 0, COMMIT_OUTPUT]
    For HALT:   [0, 0, 0, 0, COMMIT_HALT]
    For regular: [val_b0, val_b1, val_b2, val_b3, stack_size]
    """
    vm = WasmVM()
    vm.load_program(program)
    vm_trace = vm.run()

    expected = []
    ss = 0
    prev_stack_top = 0

    for entry in vm_trace:
        op_name = entry.get('op', '')

        # Structural ops that pop: track stack but skip trace step
        if op_name in ('br_if', 'if', 'drop'):
            ss -= 1
            continue
        if op_name in ('nop', 'block', 'loop', 'else', 'end', 'br'):
            continue

        val = entry.get('stack_top', 0) or 0

        if op_name == 'halt':
            expected.extend([0, 0, 0, 0, COMMIT_HALT])
            break

        vb = [val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF]

        if op_name == 'i32_const':
            ss += 1
        elif op_name in ('i32_add', 'i32_sub', 'i32_mul',
                          'i32_le_s', 'i32_ge_s', 'i32_lt_s', 'i32_gt_s',
                          'i32_eq', 'i32_ne',
                          'i32_div_s', 'i32_rem_s', 'i32_and', 'i32_or',
                          'i32_xor', 'i32_shl', 'i32_shr_s'):
            ss -= 1
        elif op_name == 'i32_eqz':
            pass  # pop 1, push 1
        elif op_name in ('output', 'output_char'):
            ss -= 1
            expected.extend([0, 0, 0, 0, COMMIT_OUTPUT])
            continue
        elif op_name == 'local_set':
            ss -= 1
            # local_set outputs the stored value (from stack before pop)
            stored_val = prev_stack_top if prev_stack_top is not None else 0
            vb = [stored_val & 0xFF, (stored_val >> 8) & 0xFF,
                  (stored_val >> 16) & 0xFF, (stored_val >> 24) & 0xFF]
        elif op_name == 'local_get':
            ss += 1
        elif op_name == 'local_tee':
            pass  # neutral

        expected.extend(vb + [ss])
        prev_stack_top = val

    return expected


def encode_program_for_training(program: list[Instruction]) -> list[int]:
    """
    Encode program for training. Uses encode_program_native for straight-line
    programs and encode_program_hybrid for control flow programs.

    For training, BAKED_BINARY should be EMPTY -- we encode all ops natively
    because we want the model to LEARN them, not bake them.
    """
    if has_control_flow(program):
        # For hybrid encoding with training data, we need to encode
        # div/rem/bitwise as their native ops, not as baked CONST.
        # Since the current encode_program_hybrid bakes these ops,
        # for training we use encode_program_native which encodes all
        # ops with their actual opcodes.
        #
        # For control flow programs, we still need encode_program_hybrid
        # to get the IP sequence. But for the program tokens, we want
        # native opcodes. So we use a modified approach:
        # encode_program_native for the tokens, but run VM for trace.
        tokens = encode_program_native(program)
    else:
        tokens = encode_program_native(program)
    return tokens


def generate_training_sample(program: list[Instruction]):
    """
    Generate a single training sample from a program.

    Returns:
        input_tokens: program_tokens (3601) + trace_tokens[:-1]
        target_tokens: trace_tokens (shifted by 1)
        program_len: length of program region (for masking)
        Or None if the program fails.
    """
    try:
        prog_tokens = encode_program_for_training(program)
        trace_tokens = build_vm_expected_trace(program)

        if len(trace_tokens) == 0:
            return None

        # Input: program_tokens + trace_tokens[:-1] (teacher forcing)
        # The model sees the program, then predicts each trace token
        # given all previous trace tokens.
        input_tokens = prog_tokens + trace_tokens[:-1]
        # Target: we only care about predicting trace tokens.
        # Pad program positions with -100 (ignored by cross-entropy)
        target_tokens = [-100] * len(prog_tokens) + trace_tokens

        return {
            'input': input_tokens,
            'target': target_tokens,
            'program_len': len(prog_tokens),
            'trace_len': len(trace_tokens),
        }
    except Exception as e:
        return None


def generate_batch(batch_size=1):
    """Generate a batch of training samples."""
    samples = []
    while len(samples) < batch_size:
        program = generate_random_program()
        sample = generate_training_sample(program)
        if sample is not None:
            samples.append(sample)
    return samples


# ============================================================
# 3. Training Loop
# ============================================================

@dataclass
class TrainingConfig:
    lr: float = 1e-4
    weight_decay: float = 0.01
    n_steps: int = 1000
    eval_every: int = 100
    batch_size: int = 1
    max_trace_len: int = 500  # max trace tokens per sample
    seed: int = 42


def make_validation_set(n_programs=20):
    """Create a fixed validation set of programs."""
    random.seed(12345)  # deterministic validation set
    val_programs = []

    # Include a mix of all program types
    generators = [
        gen_arithmetic_program,
        gen_comparison_program,
        gen_local_variable_program,
        gen_if_else_program,
        gen_while_loop_program,
        gen_mixed_program,
        gen_chained_arithmetic_program,
        gen_eqz_program,
        gen_native_bitwise_program,
        gen_native_bitwise_program,
    ]

    for i in range(n_programs):
        gen = generators[i % len(generators)]
        prog = gen()
        sample = generate_training_sample(prog)
        if sample is not None:
            val_programs.append((prog, sample))

    random.seed()  # restore randomness
    return val_programs


def evaluate(model, val_set, device):
    """Evaluate model on validation set. Returns (accuracy, avg_loss)."""
    model.eval()
    total_loss = 0.0
    total_correct = 0
    total_tokens = 0
    n_programs_correct = 0

    with torch.no_grad():
        for prog, sample in val_set:
            input_ids = torch.tensor([sample['input']], dtype=torch.long, device=device)
            target_ids = torch.tensor([sample['target']], dtype=torch.long, device=device)

            # Truncate if too long for the model
            max_len = min(input_ids.shape[1], MAX_SEQ)
            input_ids = input_ids[:, :max_len]
            target_ids = target_ids[:, :max_len]

            logits = model(input_ids)  # (1, T, vocab)

            # Only compute loss on trace positions
            trace_mask = target_ids[0] != -100
            if trace_mask.sum() == 0:
                continue

            trace_logits = logits[0][trace_mask]
            trace_targets = target_ids[0][trace_mask]

            loss = F.cross_entropy(trace_logits, trace_targets)
            total_loss += loss.item() * trace_targets.shape[0]

            # Token-level accuracy
            preds = trace_logits.argmax(dim=-1)
            correct = (preds == trace_targets).sum().item()
            total_correct += correct
            total_tokens += trace_targets.shape[0]

            # Program-level accuracy
            if correct == trace_targets.shape[0]:
                n_programs_correct += 1

    avg_loss = total_loss / max(total_tokens, 1)
    token_acc = total_correct / max(total_tokens, 1)
    prog_acc = n_programs_correct / max(len(val_set), 1)

    model.train()
    return token_acc, prog_acc, avg_loss


def train(config: TrainingConfig = None):
    """Main training loop."""
    if config is None:
        config = TrainingConfig()

    random.seed(config.seed)
    torch.manual_seed(config.seed)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Device: {device}")

    # Build model with compiled weights as starting point
    # Use smaller max_seq for training (programs are short, traces < 500 tokens)
    print("Building model with compiled weights...")
    import autoregressive_interpreter as ai
    _orig_max_seq = ai.MAX_SEQ
    ai.MAX_SEQ = 5000  # enough for program (3601) + trace (~500)
    model = build_native_interpreter()
    ai.MAX_SEQ = _orig_max_seq  # restore
    model = model.float()  # float32 for faster training (float64 not needed)
    model.train()
    model.to(device)

    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model: {n_params:,} parameters")
    print(f"Architecture: d_model={D_MODEL}, n_heads={N_HEADS}, "
          f"n_layers={N_LAYERS}, d_ffn={D_FFN}, vocab={TraceVocab.VOCAB_SIZE}")

    # Optimizer
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=config.lr,
        weight_decay=config.weight_decay,
    )

    # Validation set
    print("Generating validation set...")
    val_set = make_validation_set(20)
    print(f"Validation set: {len(val_set)} programs")

    # Initial evaluation
    tok_acc, prog_acc, val_loss = evaluate(model, val_set, device)
    print(f"\nInitial eval: tok_acc={tok_acc:.4f}, prog_acc={prog_acc:.4f}, loss={val_loss:.4f}")

    # Training
    print(f"\nStarting training for {config.n_steps} steps...")
    print("-" * 80)

    model.train()
    running_loss = 0.0
    running_correct = 0
    running_tokens = 0
    t0 = time.perf_counter()

    for step in range(1, config.n_steps + 1):
        # Generate fresh training data (online generation)
        program = generate_random_program()
        sample = generate_training_sample(program)
        if sample is None:
            continue

        input_ids = torch.tensor([sample['input']], dtype=torch.long, device=device)
        target_ids = torch.tensor([sample['target']], dtype=torch.long, device=device)

        # Truncate if too long
        max_len = min(input_ids.shape[1], MAX_SEQ)
        input_ids = input_ids[:, :max_len]
        target_ids = target_ids[:, :max_len]

        # Forward pass
        logits = model(input_ids)  # (1, T, vocab)

        # Loss on trace positions only
        trace_mask = target_ids[0] != -100
        if trace_mask.sum() == 0:
            continue

        trace_logits = logits[0][trace_mask]
        trace_targets = target_ids[0][trace_mask]

        loss = F.cross_entropy(trace_logits, trace_targets)

        # Backward pass
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        # Track metrics
        with torch.no_grad():
            preds = trace_logits.argmax(dim=-1)
            correct = (preds == trace_targets).sum().item()
            n_tokens = trace_targets.shape[0]

        running_loss += loss.item() * n_tokens
        running_correct += correct
        running_tokens += n_tokens

        # Logging
        if step % 10 == 0:
            avg_loss = running_loss / max(running_tokens, 1)
            avg_acc = running_correct / max(running_tokens, 1)
            elapsed = time.perf_counter() - t0
            print(f"  step {step:5d} | loss={avg_loss:.4f} | tok_acc={avg_acc:.4f} | "
                  f"elapsed={elapsed:.1f}s")
            running_loss = 0.0
            running_correct = 0
            running_tokens = 0

        # Evaluation
        if step % config.eval_every == 0:
            tok_acc, prog_acc, val_loss = evaluate(model, val_set, device)
            elapsed = time.perf_counter() - t0
            print(f"  >>> EVAL step {step}: tok_acc={tok_acc:.4f}, "
                  f"prog_acc={prog_acc:.4f}, val_loss={val_loss:.4f} | {elapsed:.1f}s")
            model.train()

    total_time = time.perf_counter() - t0
    print(f"\nTraining complete in {total_time:.1f}s")

    # Final evaluation
    tok_acc, prog_acc, val_loss = evaluate(model, val_set, device)
    print(f"Final eval: tok_acc={tok_acc:.4f}, prog_acc={prog_acc:.4f}, loss={val_loss:.4f}")

    return model


# ============================================================
# 4. Post-Training Evaluation
# ============================================================

def eval_test_suite(model):
    """
    Run the standard test suite plus DIV/REM/bitwise tests.
    Uses run_native which does full autoregressive generation.
    """
    print("\n" + "=" * 70)
    print("POST-TRAINING EVALUATION")
    print("=" * 70)

    # Standard tests (from test_native)
    standard_tests = [
        ("3 + 5 = 8",
         [Instruction(Op.I32_CONST, 3), Instruction(Op.I32_CONST, 5),
          Instruction(Op.I32_ADD), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("7 * 13 = 91",
         [Instruction(Op.I32_CONST, 7), Instruction(Op.I32_CONST, 13),
          Instruction(Op.I32_MUL), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("10 - 3 = 7",
         [Instruction(Op.I32_CONST, 10), Instruction(Op.I32_CONST, 3),
          Instruction(Op.I32_SUB), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("2*(3+5) = 16",
         [Instruction(Op.I32_CONST, 2), Instruction(Op.I32_CONST, 3),
          Instruction(Op.I32_CONST, 5), Instruction(Op.I32_ADD),
          Instruction(Op.I32_MUL), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("200 + 200 = 400",
         [Instruction(Op.I32_CONST, 200), Instruction(Op.I32_CONST, 200),
          Instruction(Op.I32_ADD), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("10 >= 5 = 1",
         [Instruction(Op.I32_CONST, 10), Instruction(Op.I32_CONST, 5),
          Instruction(Op.I32_GE_S), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("5 == 5 = 1",
         [Instruction(Op.I32_CONST, 5), Instruction(Op.I32_CONST, 5),
          Instruction(Op.I32_EQ), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
    ]

    # DIV/REM/bitwise tests (native WASM ops)
    native_tests = [
        ("17 % 5 = 2",
         [Instruction(Op.I32_CONST, 17), Instruction(Op.I32_CONST, 5),
          Instruction(Op.I32_REM_S), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("100 / 7 = 14",
         [Instruction(Op.I32_CONST, 100), Instruction(Op.I32_CONST, 7),
          Instruction(Op.I32_DIV_S), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("12 & 10 = 8",
         [Instruction(Op.I32_CONST, 12), Instruction(Op.I32_CONST, 10),
          Instruction(Op.I32_AND), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("12 | 10 = 14",
         [Instruction(Op.I32_CONST, 12), Instruction(Op.I32_CONST, 10),
          Instruction(Op.I32_OR), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("12 ^ 10 = 6",
         [Instruction(Op.I32_CONST, 12), Instruction(Op.I32_CONST, 10),
          Instruction(Op.I32_XOR), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("3 << 4 = 48",
         [Instruction(Op.I32_CONST, 3), Instruction(Op.I32_CONST, 4),
          Instruction(Op.I32_SHL), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
        ("48 >> 2 = 12",
         [Instruction(Op.I32_CONST, 48), Instruction(Op.I32_CONST, 2),
          Instruction(Op.I32_SHR_S), Instruction(Op.OUTPUT), Instruction(Op.HALT)]),
    ]

    all_tests = [("STANDARD", standard_tests), ("NATIVE OPS", native_tests)]
    total_passed = 0
    total_tests = 0

    for section_name, tests in all_tests:
        print(f"\n  --- {section_name} ---")
        for name, prog in tests:
            total_tests += 1
            gen, info = run_native(model, prog)
            status = "PASS" if info['match'] else "FAIL"
            if info['match']:
                total_passed += 1
            print(f"  {name:<25} {info['n_tok']:>4} tok  "
                  f"result={info['result']}  {status}")
            if not info['match']:
                exp = info['expected']
                print(f"    expected: {exp[:25]}")
                print(f"    got:      {gen[:25]}")

    print(f"\n  Result: {total_passed}/{total_tests}")
    return total_passed, total_tests


# ============================================================
# Main
# ============================================================

if __name__ == '__main__':
    print("=" * 70)
    print("WASM-in-Transformer Training Pipeline")
    print("=" * 70)
    print(f"Model:  d_model={D_MODEL}, n_heads={N_HEADS}, "
          f"n_layers={N_LAYERS}, d_ffn={D_FFN}")
    print(f"Vocab:  {TraceVocab.VOCAB_SIZE}")
    print(f"Program region: {PROG_LEN} tokens + 1 SEP = {PROG_LEN + 1}")
    print(f"Trace start: position {TRACE_START}")
    print(f"Step size: {STEP_SIZE} tokens/step")
    print()

    config = TrainingConfig(
        lr=1e-4,
        weight_decay=0.01,
        n_steps=1000,
        eval_every=100,
        batch_size=1,
        seed=42,
    )

    # Train
    model = train(config)

    # Post-training evaluation
    model.eval()
    eval_test_suite(model)
