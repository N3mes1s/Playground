"""Training v2: full operand range + complex programs to prevent memorization."""
import torch, time, random, re, sys

import autoregressive_interpreter as ai
ai.MAX_INST = 50; ai.PROG_LEN = 300; ai.SEP_POS = 300; ai.TRACE_START = 301; ai.MAX_SEQ = 1000

from model import VanillaTransformer
from compiler import TraceVocab
from wasm_vm import Instruction, Op, WasmVM
from autoregressive_interpreter import encode_program_native
from train import generate_training_sample, generate_random_program

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


def gen_single_full_range():
    """Single op with FULL byte range 0-255."""
    op = random.choice(list(OP_CODES.keys()))
    a = random.randint(0, 255)  # FULL RANGE
    b = random.randint(1, 255) if op in ("div", "rem") else \
        (random.randint(0, 7) if op in ("shl", "shr") else random.randint(0, 255))
    return op, a, b


def gen_chain():
    """Chain of 2-4 operations."""
    n_ops = random.randint(2, 4)
    opcodes = [0x41]; operands = [random.randint(0, 100)]
    for _ in range(n_ops):
        op = random.choice(["add", "sub", "mul"])
        opcodes.extend([0x41, OP_CODES[op]])
        operands.extend([random.randint(1, 20), 0])
    opcodes.extend([0xFF, 0x00])
    operands.extend([0, 0])

    wasm_prog = [Instruction(Op.I32_CONST, operands[0])]
    idx = 1
    for i in range(1, len(opcodes)):
        if opcodes[i] == 0x41:
            wasm_prog.append(Instruction(Op.I32_CONST, operands[idx]))
            idx += 1
        elif opcodes[i] in (0x6A, 0x6B, 0x6C):
            op_map = {0x6A: Op.I32_ADD, 0x6B: Op.I32_SUB, 0x6C: Op.I32_MUL}
            wasm_prog.append(Instruction(op_map[opcodes[i]]))
            idx += 1
        elif opcodes[i] == 0xFF:
            wasm_prog.append(Instruction(Op.OUTPUT))
        elif opcodes[i] == 0x00:
            wasm_prog.append(Instruction(Op.HALT))
    return wasm_prog


def gen_locals():
    """Program using local variables."""
    op = random.choice(list(OP_WASM.keys()))
    a = random.randint(0, 200)
    b = random.randint(1, 100) if op in ("div", "rem") else \
        (random.randint(0, 7) if op in ("shl", "shr") else random.randint(0, 200))
    return [Instruction(Op.I32_CONST, a), Instruction(Op.LOCAL_SET, 0),
            Instruction(Op.I32_CONST, b), Instruction(Op.LOCAL_SET, 1),
            Instruction(Op.LOCAL_GET, 0), Instruction(Op.LOCAL_GET, 1),
            Instruction(OP_WASM[op]), Instruction(Op.OUTPUT), Instruction(Op.HALT)]


def make_sample(prog):
    """Generate training sample from a program."""
    sample = generate_training_sample(prog)
    if sample:
        inp, tgt = sample["input"], sample["target"]
        return inp, tgt
    return None, None


def make_fast_sample():
    """Generate a sample using Rust fast VM."""
    kind = random.choice(["single", "single", "single", "chain", "locals"])

    if kind == "single":
        op, a, b = gen_single_full_range()
        if HAS_RUST:
            trace = fast_vm_trace([0x41, 0x41, OP_CODES[op], 0xFF, 0x00], [a, b, 0, 0, 0])
            prog = [Instruction(Op.I32_CONST, a), Instruction(Op.I32_CONST, b),
                    Instruction(OP_WASM[op]), Instruction(Op.OUTPUT), Instruction(Op.HALT)]
            prog_tokens = encode_program_native(prog)
            trace_tokens = [int(t) for t in trace]
            inp = prog_tokens + trace_tokens[:-1]
            tgt = [-100] * (len(prog_tokens) - 1) + trace_tokens
            return inp, tgt
        else:
            prog = [Instruction(Op.I32_CONST, a), Instruction(Op.I32_CONST, b),
                    Instruction(OP_WASM[op]), Instruction(Op.OUTPUT), Instruction(Op.HALT)]
            return make_sample(prog)

    elif kind == "chain":
        prog = gen_chain()
        return make_sample(prog)

    elif kind == "locals":
        prog = gen_locals()
        return make_sample(prog)

    return None, None


if __name__ == "__main__":
    random.seed(int(time.time())); torch.manual_seed(int(time.time()))
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}", flush=True)

    checkpoint = sys.argv[1] if len(sys.argv) > 1 else None

    model = VanillaTransformer(vocab=TraceVocab.VOCAB_SIZE, d_model=128, n_heads=64,
        n_layers=12, d_ffn=512, max_seq_len=1000, pe_mode="learned").float().to(device)

    if checkpoint:
        model.load_state_dict(torch.load(checkpoint, map_location=device, weights_only=True))
        print(f"Loaded checkpoint: {checkpoint}", flush=True)
    else:
        print("Training from scratch", flush=True)

    model.train()
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model: {n_params:,} params", flush=True)
    print(f"Rust fast VM: {HAS_RUST}", flush=True)

    optimizer = torch.optim.AdamW(model.parameters(), lr=3e-4, weight_decay=0.01)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=500000)

    t0 = time.time(); rl, ra, rn = 0, 0, 0; best = 0

    for step in range(1, 500001):
        inp, tgt = make_fast_sample()
        if inp is None: continue

        ml = min(len(inp), len(tgt))
        x = torch.tensor([inp[:ml]], dtype=torch.long, device=device)
        y = torch.tensor([tgt[:ml]], dtype=torch.long, device=device)

        logits = model(x)
        mask = y[0] != -100
        if mask.sum() == 0: continue

        loss = torch.nn.functional.cross_entropy(logits[0][mask], y[0][mask])
        if torch.isnan(loss) or loss.item() > 50:
            optimizer.zero_grad(); continue

        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step(); scheduler.step(); optimizer.zero_grad()

        acc = (logits[0][mask].argmax(-1) == y[0][mask]).float().mean().item()
        rl += loss.item(); ra += acc; rn += 1

        if step % 10000 == 0:
            aa = ra / rn
            print(f"Step {step:7d}: loss={rl/rn:.4f} acc={aa:.4f} lr={scheduler.get_last_lr()[0]:.6f} ({time.time()-t0:.0f}s)", flush=True)
            if aa > best:
                best = aa
                torch.save(model.state_dict(), "/root/wasm_v2_best.pt")
                print(f"  -> New best: {best:.4f}", flush=True)
            rl, ra, rn = 0, 0, 0

            # Quick eval: in-distribution AND out-of-distribution
            model.eval()
            test_ops = [
                # In-distribution (0-100)
                (3, 5, Op.I32_ADD, 8), (7, 13, Op.I32_MUL, 91), (17, 5, Op.I32_REM_S, 2),
                # Out-of-distribution (100-255)
                (150, 180, Op.I32_ADD, 330 & 0xFF), (200, 120, Op.I32_SUB, 80),
                (15, 17, Op.I32_MUL, 255), (180, 11, Op.I32_DIV_S, 16),
                (199, 13, Op.I32_REM_S, 4), (170, 140, Op.I32_AND, 136),
            ]
            passed = 0
            for a, b, op, exp in test_ops:
                prog = [Instruction(Op.I32_CONST, a), Instruction(Op.I32_CONST, b),
                        Instruction(op), Instruction(Op.OUTPUT), Instruction(Op.HALT)]
                sample = generate_training_sample(prog)
                if not sample: continue
                et = [t for t in sample["target"] if t != -100]
                with torch.no_grad():
                    ids = torch.tensor([sample["input"][:301]], dtype=torch.long, device=device)
                    for i in range(len(et)):
                        lo = model(ids); ids = torch.cat([ids, lo[0:1, -1:].argmax(-1)], dim=1)
                if ids[0, 301:].tolist()[:len(et)] == et: passed += 1
            print(f"  Eval: {passed}/{len(test_ops)} (in+out-of-distribution)", flush=True)
            model.train()

            if passed >= len(test_ops):
                print("ALL PASS INCLUDING OOD!", flush=True)
                break

    print(f"Done in {time.time()-t0:.0f}s, best={best:.4f}", flush=True)
    torch.save(model.state_dict(), "/root/wasm_v2_final.pt")
