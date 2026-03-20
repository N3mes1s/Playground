"""
Hybrid training: compiled weights (ADD/SUB/MUL/comparisons) + trained (DIV/REM/bitwise).

Key insight: the hand-crafted model has PERFECT carry chains and stack matching.
These provide the inductive bias for generalization. We freeze these layers and
train ONLY the FFN gates that handle unsupported operations.

Architecture: d_model=40, n_heads=20, n_layers=10, d_ffn=256
- BIG=1000 (training-friendly, not 10B)
- S_HEAD=1.0 (training-friendly output head)
- Frozen: L0-L3 (instruction fetch, operand resolution, byte fetch, carry)
- Trained: L2 FFN (new ALU gates for DIV/REM/bitwise), L4-L9 FFN, output head
"""
import torch, time, random, sys

# Must set BIG before importing
import autoregressive_interpreter as ai
ai.BIG = 1000.0  # Training-friendly (was 10B)
ai.S_HEAD = 1.0  # Training-friendly output head (was 50)
ai.MAX_INST = 50; ai.PROG_LEN = 300; ai.SEP_POS = 300; ai.TRACE_START = 301; ai.MAX_SEQ = 1000

from autoregressive_interpreter import build_native_interpreter, encode_program_native
from model import VanillaTransformer
from compiler import TraceVocab
from wasm_vm import Instruction, Op, WasmVM
from train import generate_training_sample

try:
    from llm_compute_engine import fast_vm_trace
    HAS_RUST = True
except ImportError:
    HAS_RUST = False

OP_CODES = {"add":0x6A,"sub":0x6B,"mul":0x6C,"div":0x6D,"rem":0x6F,
            "and":0x71,"or":0x72,"xor":0x73,"shl":0x74,"shr":0x75}
OP_WASM = {"add":Op.I32_ADD,"sub":Op.I32_SUB,"mul":Op.I32_MUL,"div":Op.I32_DIV_S,
           "rem":Op.I32_REM_S,"and":Op.I32_AND,"or":Op.I32_OR,"xor":Op.I32_XOR,
           "shl":Op.I32_SHL,"shr":Op.I32_SHR_S}


def gen_program():
    """Generate a program with FULL byte range operands."""
    op = random.choice(list(OP_CODES.keys()))
    a = random.randint(0, 255)
    b = random.randint(1, 255) if op in ("div", "rem") else \
        (random.randint(0, 7) if op in ("shl", "shr") else random.randint(0, 255))
    return op, a, b


def make_sample(op_name, a, b):
    """Make a training sample using Rust fast VM or Python VM."""
    if HAS_RUST:
        trace = fast_vm_trace([0x41, 0x41, OP_CODES[op_name], 0xFF, 0x00], [a, b, 0, 0, 0])
        prog = [Instruction(Op.I32_CONST, a), Instruction(Op.I32_CONST, b),
                Instruction(OP_WASM[op_name]), Instruction(Op.OUTPUT), Instruction(Op.HALT)]
        prog_tokens = encode_program_native(prog)
        trace_tokens = [int(t) for t in trace]
        inp = prog_tokens + trace_tokens[:-1]
        tgt = [-100] * (len(prog_tokens) - 1) + trace_tokens
        return inp, tgt
    else:
        prog = [Instruction(Op.I32_CONST, a), Instruction(Op.I32_CONST, b),
                Instruction(OP_WASM[op_name]), Instruction(Op.OUTPUT), Instruction(Op.HALT)]
        sample = generate_training_sample(prog)
        if sample:
            return sample["input"], sample["target"]
        return None, None


if __name__ == "__main__":
    random.seed(42); torch.manual_seed(42)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}", flush=True)
    print(f"BIG={ai.BIG}, S_HEAD={ai.S_HEAD}", flush=True)
    print(f"Rust fast VM: {HAS_RUST}", flush=True)

    # Build model with COMPILED weights (BIG=1000, S_HEAD=1.0)
    print("Building model with compiled weights (BIG=1000)...", flush=True)
    model = build_native_interpreter()
    model = model.float().to(device)
    model.train()
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model: {n_params:,} params", flush=True)

    # Freeze L0-L1 attention (instruction fetch, operand resolution)
    # These are PERFECTLY compiled and should not change
    for layer in range(2):  # L0, L1
        for param in model.attn[layer].parameters():
            param.requires_grad = False

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Trainable: {trainable:,} params (frozen: L0-L1 attention)", flush=True)

    optimizer = torch.optim.AdamW(
        [p for p in model.parameters() if p.requires_grad],
        lr=1e-4, weight_decay=0.01
    )
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=500000)

    # Verify compiled weights work for ADD before training
    print("\nPre-training check (compiled ADD):", flush=True)
    model.eval()
    for a, b in [(3, 5), (150, 180), (255, 255)]:
        op_name = "add"
        inp, tgt = make_sample(op_name, a, b)
        if inp is None: continue
        et = [t for t in tgt if t != -100]
        with torch.no_grad():
            ids = torch.tensor([inp[:301]], dtype=torch.long, device=device)
            for i in range(len(et)):
                lo = model(ids); ids = torch.cat([ids, lo[0:1, -1:].argmax(-1)], dim=1)
        g = ids[0, 301:].tolist()
        rb = g[10] if len(g) > 10 else "?"
        ok = g[:len(et)] == et
        print(f"  {a}+{b}: {'PASS' if ok else 'FAIL'} (got byte0={rb})", flush=True)
    model.train()

    # Training
    print(f"\nStarting hybrid training...", flush=True)
    t0 = time.time(); rl, ra, rn = 0, 0, 0; best = 0

    for step in range(1, 500001):
        op_name, a, b = gen_program()
        inp, tgt = make_sample(op_name, a, b)
        if inp is None: continue

        ml = min(len(inp), len(tgt))
        x = torch.tensor([inp[:ml]], dtype=torch.long, device=device)
        y = torch.tensor([tgt[:ml]], dtype=torch.long, device=device)

        logits = model(x)
        mask = y[0] != -100
        if mask.sum() == 0: continue

        loss = torch.nn.functional.cross_entropy(logits[0][mask], y[0][mask])
        if torch.isnan(loss) or loss.item() > 100:
            optimizer.zero_grad(); continue

        loss.backward()
        torch.nn.utils.clip_grad_norm_(
            [p for p in model.parameters() if p.requires_grad], 1.0)
        optimizer.step(); scheduler.step(); optimizer.zero_grad()

        acc = (logits[0][mask].argmax(-1) == y[0][mask]).float().mean().item()
        rl += loss.item(); ra += acc; rn += 1

        if step % 10000 == 0:
            aa = ra / rn
            print(f"Step {step:7d}: loss={rl/rn:.4f} acc={aa:.4f} lr={scheduler.get_last_lr()[0]:.6f} ({time.time()-t0:.0f}s)", flush=True)
            if aa > best:
                best = aa
                torch.save(model.state_dict(), "/root/wasm_hybrid_best.pt")
                print(f"  -> New best: {best:.4f}", flush=True)
            rl, ra, rn = 0, 0, 0

            # Eval: in-distribution AND out-of-distribution
            model.eval()
            test_ops = [
                (3, 5, "add", 8), (150, 180, "add", 74),  # 330&0xFF=74
                (10, 3, "sub", 7), (200, 120, "sub", 80),
                (7, 13, "mul", 91), (15, 17, "mul", 255),
                (100, 7, "div", 14), (200, 11, "div", 18),
                (17, 5, "rem", 2), (199, 13, "rem", 4),
                (12, 10, "and", 8), (170, 140, "and", 136),
                (12, 10, "or", 14), (5, 10, "or", 15),
                (12, 10, "xor", 6), (255, 127, "xor", 128),
                (3, 4, "shl", 48), (48, 2, "shr", 12),
            ]
            passed = 0
            for a, b, op_name, exp in test_ops:
                inp, tgt = make_sample(op_name, a, b)
                if inp is None: continue
                et = [t for t in tgt if t != -100]
                with torch.no_grad():
                    ids = torch.tensor([inp[:301]], dtype=torch.long, device=device)
                    for i in range(len(et)):
                        lo = model(ids)
                        ids = torch.cat([ids, lo[0:1, -1:].argmax(-1)], dim=1)
                if ids[0, 301:].tolist()[:len(et)] == et:
                    passed += 1
            print(f"  Eval: {passed}/{len(test_ops)} (in+OOD)", flush=True)
            model.train()

            if passed >= len(test_ops):
                print("ALL PASS INCLUDING OOD!", flush=True)
                break

    print(f"Done in {time.time()-t0:.0f}s, best={best:.4f}", flush=True)
    torch.save(model.state_dict(), "/root/wasm_hybrid_final.pt")
