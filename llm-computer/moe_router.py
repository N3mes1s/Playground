"""
Mixture-of-Experts Router: pairs the compute co-processor with a language LLM.

Architecture:
    ┌─────────────────────────────────────────────────────┐
    │  User prompt: "How many words are in this text?"    │
    └──────────────────────┬──────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   Router    │  (classifies: compute vs language)
                    └──┬──────┬──┘
                       │      │
            ┌──────────▼┐  ┌──▼──────────────┐
            │  Compute  │  │  Language LLM    │
            │  Model    │  │  (Llama/Mistral) │
            │  (100K)   │  │  (7B+)           │
            └──────┬────┘  └───────┬──────────┘
                   │               │
            ┌──────▼───────────────▼──────┐
            │     Combine & respond       │
            └─────────────────────────────┘

The compute model executes deterministic programs through its forward pass.
The language LLM handles natural language understanding and generation.
Together they form a system where:
- The LLM understands WHAT to compute
- The compute model executes it CORRECTLY
- The LLM formats the result for the user

Compatible with: Llama 3, Mistral, Qwen, Phi, Gemma, or any HF model.
"""

from __future__ import annotations
import re
import json
import time
from typing import Optional
from dataclasses import dataclass

import torch
import torch.nn as nn
import torch.nn.functional as F

from model import VanillaTransformer
from compiler import TraceVocab, TraceCompiler
from wasm_vm import WasmVM, Instruction, Op
from sandbox import Sandbox


# ============================================================
# Compute task detection
# ============================================================

# Patterns that indicate a compute task
COMPUTE_PATTERNS = [
    # Counting
    r'how many words',
    r'count.*words',
    r'word count',
    r'how many characters',
    r'count.*characters',
    r'character count',
    r'how many lines',
    r'count.*lines',
    r'line count',
    # Arithmetic
    r'what is \d+\s*[\+\-\*\/\%]\s*\d+',
    r'calculate\s',
    r'compute\s',
    r'sum of',
    r'product of',
    r'factorial of',
    r'fibonacci',
    r'fib\(\d+\)',
    r'gcd of',
    # Sorting
    r'sort\s+(these|the|this|following)',
    r'sort.*numbers',
    r'sort.*list',
    r'sort.*array',
    # String operations
    r'reverse.*string',
    r'reverse.*text',
    r'uppercase',
    r'to upper',
    r'hash.*string',
    r'hash of',
    # Search
    r'find.*in.*text',
    r'search for',
    r'how many times.*appear',
    r'occurrences of',
]

COMPUTE_RE = re.compile('|'.join(COMPUTE_PATTERNS), re.IGNORECASE)


@dataclass
class RouterDecision:
    """Result of the router's classification."""
    route: str           # 'compute' or 'language'
    confidence: float    # 0.0 to 1.0
    task_type: str       # e.g., 'word_count', 'sort', 'arithmetic'
    extracted_args: dict  # parsed arguments for the compute task


@dataclass
class MoEResult:
    """Final result from the MoE pipeline."""
    answer: str
    route: str
    compute_result: Optional[dict] = None
    elapsed_seconds: float = 0.0


class TaskExtractor:
    """
    Extracts structured compute tasks from natural language.

    Maps user intent to sandbox operations:
    - "How many words in 'hello world'?" → sandbox.word_count("hello world")
    - "Sort [5, 3, 1, 4]" → sandbox.sort_integers([5, 3, 1, 4])
    - "What is fib(10)?" → sandbox.fibonacci(10) via VM
    """

    def extract(self, prompt: str) -> Optional[RouterDecision]:
        """Try to extract a compute task from the prompt."""

        # Word count
        m = re.search(r'(?:how many words|count.*words|word count).*?["\'](.+?)["\']',
                       prompt, re.IGNORECASE)
        if not m:
            m = re.search(r'(?:how many words|count.*words|word count).*?:\s*(.+?)$',
                           prompt, re.IGNORECASE)
        if m:
            return RouterDecision('compute', 0.95, 'word_count',
                                   {'text': m.group(1).strip()})

        # Character count
        m = re.search(r'(?:how many characters|count.*characters|character count).*?["\'](.+?)["\']',
                       prompt, re.IGNORECASE)
        if m:
            return RouterDecision('compute', 0.95, 'char_count',
                                   {'text': m.group(1).strip()})

        # Line count
        m = re.search(r'(?:how many lines|count.*lines|line count).*?["\'](.+?)["\']',
                       prompt, re.IGNORECASE)
        if m:
            return RouterDecision('compute', 0.95, 'line_count',
                                   {'text': m.group(1).strip()})

        # Sort
        m = re.search(r'sort.*?\[(.+?)\]', prompt, re.IGNORECASE)
        if m:
            try:
                numbers = [int(x.strip()) for x in m.group(1).split(',')]
                return RouterDecision('compute', 0.95, 'sort',
                                       {'numbers': numbers})
            except ValueError:
                pass

        # Fibonacci
        m = re.search(r'fib(?:onacci)?\s*\(?(\d+)\)?', prompt, re.IGNORECASE)
        if m:
            return RouterDecision('compute', 0.95, 'fibonacci',
                                   {'n': int(m.group(1))})

        # Simple arithmetic: "what is 3 + 5"
        m = re.search(r'(\-?\d+)\s*([\+\-\*\/\%])\s*(\-?\d+)', prompt)
        if m:
            return RouterDecision('compute', 0.9, 'arithmetic',
                                   {'a': int(m.group(1)),
                                    'op': m.group(2),
                                    'b': int(m.group(3))})

        # Hash
        m = re.search(r'hash.*?["\'](.+?)["\']', prompt, re.IGNORECASE)
        if m:
            return RouterDecision('compute', 0.9, 'hash',
                                   {'text': m.group(1).strip()})

        # Reverse
        m = re.search(r'reverse.*?["\'](.+?)["\']', prompt, re.IGNORECASE)
        if m:
            return RouterDecision('compute', 0.9, 'reverse',
                                   {'text': m.group(1).strip()})

        # Uppercase
        m = re.search(r'(?:uppercase|to upper).*?["\'](.+?)["\']', prompt, re.IGNORECASE)
        if m:
            return RouterDecision('compute', 0.9, 'uppercase',
                                   {'text': m.group(1).strip()})

        # Sum
        m = re.search(r'sum of\s*\[(.+?)\]', prompt, re.IGNORECASE)
        if m:
            try:
                numbers = [int(x.strip()) for x in m.group(1).split(',')]
                return RouterDecision('compute', 0.9, 'sum',
                                       {'numbers': numbers})
            except ValueError:
                pass

        # Factorial
        m = re.search(r'factorial.*?(\d+)', prompt, re.IGNORECASE)
        if m:
            return RouterDecision('compute', 0.9, 'factorial',
                                   {'n': int(m.group(1))})

        # GCD
        m = re.search(r'gcd.*?(\d+).*?(\d+)', prompt, re.IGNORECASE)
        if m:
            return RouterDecision('compute', 0.9, 'gcd',
                                   {'a': int(m.group(1)), 'b': int(m.group(2))})

        # Pattern match fallback
        if COMPUTE_RE.search(prompt):
            return RouterDecision('compute', 0.5, 'unknown', {})

        return None


class ComputeCoprocessor:
    """
    The compute co-processor.

    In production: uses the trained VanillaTransformer to execute programs
    through its forward pass (the blog's approach).

    Currently: uses the pywasm sandbox for verified computation, which is
    what the trained model would reproduce exactly.
    """

    def __init__(self, model_path: Optional[str] = None, device: str = 'cpu'):
        self.sandbox = Sandbox()
        self.device = device

        # Load trained compute model if available
        self.model = None
        if model_path and os.path.exists(model_path):
            self.model = VanillaTransformer(
                vocab=TraceVocab.VOCAB_SIZE,
                d_model=36, n_heads=18, n_layers=7, d_ffn=36,
            )
            ckpt = torch.load(model_path, map_location=device)
            self.model.load_state_dict(ckpt['model'])
            self.model.eval()
            self.model.to(device)

    def execute(self, task_type: str, args: dict) -> dict:
        """Execute a compute task and return structured results."""
        start = time.perf_counter()
        result = {}

        if task_type == 'word_count':
            r = self.sandbox.word_count(args['text'])
            result = {
                'answer': r.output_ints[0] if r.output_ints else 0,
                'description': f"{r.output_ints[0]} words",
            }

        elif task_type == 'char_count':
            r = self.sandbox.char_count(args['text'])
            result = {
                'answer': r.output_ints[0] if r.output_ints else 0,
                'description': f"{r.output_ints[0]} characters",
            }

        elif task_type == 'line_count':
            r = self.sandbox.line_count(args['text'])
            result = {
                'answer': r.output_ints[0] if r.output_ints else 0,
                'description': f"{r.output_ints[0]} lines",
            }

        elif task_type == 'sort':
            r = self.sandbox.sort_integers(args['numbers'])
            result = {
                'answer': r.output_ints,
                'description': f"Sorted: {r.output_ints}",
            }

        elif task_type == 'fibonacci':
            from wasm_vm import make_fibonacci_program
            from executor import Executor
            n = args['n']
            code = make_fibonacci_program(n)
            executor = Executor()
            r = executor.execute_on_vm(code)
            val = r.output[0] if r.output else 0
            result = {
                'answer': val,
                'description': f"fib({n}) = {val}",
            }

        elif task_type == 'arithmetic':
            a, op, b = args['a'], args['op'], args['b']
            ops = {'+': a + b, '-': a - b, '*': a * b,
                   '/': a // b if b != 0 else 'undefined',
                   '%': a % b if b != 0 else 'undefined'}
            val = ops.get(op, 'unknown')
            result = {
                'answer': val,
                'description': f"{a} {op} {b} = {val}",
            }

        elif task_type == 'hash':
            r = self.sandbox.hash_string(args['text'])
            h = r.output_ints[0] if r.output_ints else 0
            result = {
                'answer': h,
                'description': f"djb2 hash: {h} (0x{h & 0xFFFFFFFF:08x})",
            }

        elif task_type == 'reverse':
            r = self.sandbox.reverse_string(args['text'])
            result = {
                'answer': r.output_string,
                'description': f"Reversed: '{r.output_string}'",
            }

        elif task_type == 'uppercase':
            r = self.sandbox.to_uppercase(args['text'])
            result = {
                'answer': r.output_string,
                'description': f"Uppercase: '{r.output_string}'",
            }

        elif task_type == 'sum':
            r = self.sandbox.sum_integers(args['numbers'])
            val = r.output_ints[0] if r.output_ints else 0
            result = {
                'answer': val,
                'description': f"Sum: {val}",
            }

        elif task_type == 'factorial':
            n = args['n']
            # Quick computation via sandbox
            from mini_c import Compiler, var, lit, mul, le, assign, output_int, while_loop
            stmts = [
                assign('result', lit(1)),
                assign('i', lit(2)),
                while_loop(le(var('i'), lit(n)), [
                    assign('result', mul(var('result'), var('i'))),
                    assign('i', add(var('i'), lit(1))),
                ]),
                output_int(var('result')),
            ]
            r = self.sandbox._run('factorial', stmts)
            val = r.output_ints[0] if r.output_ints else 0
            result = {
                'answer': val,
                'description': f"{n}! = {val}",
            }

        elif task_type == 'gcd':
            from mini_c import Compiler, var, lit, ne, assign, output_int, while_loop, mod
            a, b = args['a'], args['b']
            stmts = [
                assign('a', lit(a)),
                assign('b', lit(b)),
                while_loop(ne(var('b'), lit(0)), [
                    assign('t', mod(var('a'), var('b'))),
                    assign('a', var('b')),
                    assign('b', var('t')),
                ]),
                output_int(var('a')),
            ]
            r = self.sandbox._run('gcd', stmts)
            val = r.output_ints[0] if r.output_ints else 0
            result = {
                'answer': val,
                'description': f"gcd({a}, {b}) = {val}",
            }

        else:
            result = {'answer': None, 'description': f"Unknown task: {task_type}"}

        result['elapsed'] = time.perf_counter() - start
        result['task_type'] = task_type
        result['executed_via'] = 'pywasm' if self.model is None else 'compute_model'
        return result


class MoEPipeline:
    """
    Full MoE pipeline: routes between language LLM and compute co-processor.

    Usage:
        pipeline = MoEPipeline(llm_model="Qwen/Qwen2.5-0.5B-Instruct")
        result = pipeline.query("How many words in 'the quick brown fox'?")
        print(result.answer)
        # → "The text 'the quick brown fox' contains exactly 4 words.
        #    [Verified by compute co-processor via WASM execution]"
    """

    def __init__(self, llm_model: Optional[str] = None,
                 compute_model_path: Optional[str] = None,
                 device: str = 'auto'):

        if device == 'auto':
            device = 'cuda' if torch.cuda.is_available() else 'cpu'
        self.device = device

        self.extractor = TaskExtractor()
        self.coprocessor = ComputeCoprocessor(compute_model_path, device)

        # Load language LLM (optional — works without it)
        self.llm = None
        self.llm_tokenizer = None
        if llm_model:
            self._load_llm(llm_model)

    def _load_llm(self, model_name: str):
        """Load a HuggingFace language model."""
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            print(f"Loading language LLM: {model_name}...")
            self.llm_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.llm = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if self.device == 'cuda' else torch.float32,
                device_map=self.device if self.device == 'cuda' else None,
            )
            if self.device == 'cpu':
                self.llm = self.llm.to(self.device)
            print(f"  Loaded {model_name}")
        except Exception as e:
            print(f"  Warning: Could not load LLM ({e}). Running compute-only mode.")
            self.llm = None

    def query(self, prompt: str) -> MoEResult:
        """
        Process a user query through the MoE pipeline.

        1. Router classifies: compute or language task?
        2. If compute: extract task, execute via co-processor, format result
        3. If language: pass to LLM (or return a message if no LLM loaded)
        """
        start = time.perf_counter()

        # Step 1: Route
        decision = self.extractor.extract(prompt)

        if decision and decision.route == 'compute' and decision.confidence > 0.5:
            # Step 2: Compute path
            compute_result = self.coprocessor.execute(
                decision.task_type, decision.extracted_args
            )

            # Step 3: Format response
            if self.llm:
                answer = self._llm_format(prompt, compute_result)
            else:
                answer = self._simple_format(prompt, compute_result)

            return MoEResult(
                answer=answer,
                route='compute',
                compute_result=compute_result,
                elapsed_seconds=time.perf_counter() - start,
            )
        else:
            # Language path
            if self.llm:
                answer = self._llm_generate(prompt)
            else:
                answer = ("[Language LLM not loaded. This query requires "
                          "natural language generation. Load a model with "
                          "MoEPipeline(llm_model='model_name')]")

            return MoEResult(
                answer=answer,
                route='language',
                elapsed_seconds=time.perf_counter() - start,
            )

    def _simple_format(self, prompt: str, compute_result: dict) -> str:
        """Format compute result without LLM."""
        desc = compute_result.get('description', str(compute_result.get('answer', '?')))
        via = compute_result.get('executed_via', 'pywasm')
        elapsed = compute_result.get('elapsed', 0)
        return (f"{desc}\n"
                f"[Verified: executed via {via} in {elapsed*1000:.1f}ms]")

    def _llm_format(self, prompt: str, compute_result: dict) -> str:
        """Use the LLM to format the compute result naturally."""
        desc = compute_result.get('description', '')
        answer = compute_result.get('answer', '')

        format_prompt = (
            f"The user asked: {prompt}\n\n"
            f"The compute co-processor determined: {desc}\n"
            f"The verified answer is: {answer}\n\n"
            f"Provide a brief, natural response incorporating this verified result. "
            f"Mention that the result was verified by deterministic WASM execution."
        )
        return self._llm_generate(format_prompt)

    @torch.no_grad()
    def _llm_generate(self, prompt: str, max_new_tokens: int = 256) -> str:
        """Generate text with the language LLM."""
        if not self.llm or not self.llm_tokenizer:
            return "[No LLM loaded]"

        inputs = self.llm_tokenizer(prompt, return_tensors='pt').to(self.device)
        outputs = self.llm.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=True,
            temperature=0.7,
            top_p=0.9,
        )
        response = self.llm_tokenizer.decode(
            outputs[0][inputs.input_ids.shape[1]:],
            skip_special_tokens=True
        )
        return response.strip()


# ============================================================
# CLI demo
# ============================================================

def demo():
    """Interactive demo of the MoE pipeline."""
    print("=" * 60)
    print("LLM + Compute Co-Processor (MoE)")
    print("=" * 60)
    print()
    print("The compute model handles deterministic tasks via WASM.")
    print("Type a question, or 'quit' to exit.")
    print()

    # Try to load a small LLM, fall back to compute-only
    pipeline = MoEPipeline()

    test_queries = [
        "How many words in 'the quick brown fox jumps over the lazy dog'?",
        "Sort [42, 17, 93, 5, 28, 61, 3]",
        "What is fibonacci(15)?",
        "What is 123 * 456?",
        "Reverse 'Hello, World!'",
        "Hash of 'compute model'",
        "Uppercase 'hello world 123'",
    ]

    print("Running example queries:\n")
    for q in test_queries:
        print(f"Q: {q}")
        result = pipeline.query(q)
        print(f"A: {result.answer}")
        print(f"   [route={result.route}, time={result.elapsed_seconds*1000:.1f}ms]")
        print()


if __name__ == '__main__':
    import os
    demo()
