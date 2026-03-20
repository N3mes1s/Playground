"""
Run the weight compiler benchmark on Modal (cloud GPU).

Usage:
    modal run run_modal.py
    modal run run_modal.py --max-tokens 1000
"""

import modal

app = modal.App("llm-compute-benchmark")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("torch", "numpy", "pywasm>=1.0.0")
    .add_local_dir(".", remote_path="/root/llm-computer")
)


@app.function(image=image, gpu="A10G", timeout=3600)
def benchmark(max_tokens: int = 500):
    """Run the full benchmark on GPU."""
    import sys
    sys.path.insert(0, "/root/llm-computer")

    from weight_compiler import run_tests
    run_tests(max_tokens_limit=max_tokens)


@app.function(image=image, gpu="A10G", timeout=1800)
def compile_and_run(program_type: str, *args):
    """Compile and run a specific program on GPU."""
    import sys
    sys.path.insert(0, "/root/llm-computer")

    from weight_compiler import compile_and_verify
    from wasm_vm import (make_addition_program, make_multiplication_program,
                          make_fibonacci_program)

    if program_type == 'add':
        prog = make_addition_program(int(args[0]), int(args[1]))
        name = f"{args[0]} + {args[1]}"
    elif program_type == 'mul':
        prog = make_multiplication_program(int(args[0]), int(args[1]))
        name = f"{args[0]} * {args[1]}"
    elif program_type == 'fib':
        prog = make_fibonacci_program(int(args[0]))
        name = f"fib({args[0]})"
    else:
        print(f"Unknown: {program_type}")
        return

    info = compile_and_verify(name, prog)
    print(f"{name} = {info['result']}")
    print(f"  Tokens: {info['n_tok']}, d_model: {info['d_model']}, params: {info['n_params']:,}")
    print(f"  Compile: {info['compile_sec']:.3f}s, Generate: {info['generate_sec']:.3f}s")
    print(f"  Throughput: {info['tok_per_sec']:,.0f} tok/s")
    print(f"  Correct: {info['match']}")
    return info


@app.local_entrypoint()
def main(max_tokens: int = 500):
    """Run benchmark on Modal GPU."""
    print(f"Launching benchmark on Modal GPU (max_tokens={max_tokens})...")
    benchmark.remote(max_tokens=max_tokens)
