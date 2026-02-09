"""
Modal GPU service for VulnLLM-R-7B vulnerability analysis.

Deploys the UCSB-SURFI/VulnLLM-R-7B model on Modal with GPU acceleration
using vLLM for fast inference.

Uses the official VulnLLM-R prompt strategy:
- Structured 4-step chain-of-thought reasoning
- CWE-aware policy constraints per language
- Strict #judge/#type output format
- Multi-pass analysis: discovery pass -> enriched final pass

Usage:
    modal deploy modal_service.py
    modal serve modal_service.py
"""

import re
import modal

MODEL_ID = "UCSB-SURFI/VulnLLM-R-7B"
GPU_TYPE = "A100-40GB"

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "vllm==0.8.2",
        "torch==2.6.0",
        "transformers==4.48.3",
        "huggingface_hub",
        "fastapi[standard]",
    )
)

app = modal.App("vulnllm-analyzer", image=image)

# --- Prompt templates matching VulnLLM-R's official test harness ---

# System prompt for Qwen-based models (VulnLLM-R is fine-tuned from Qwen2.5-7B)
SYSTEM_PROMPT = "You are a helpful and harmless assistant. You are Qwen developed by Alibaba. You should think step-by-step."

# Structured CoT procedure from the paper (enhanced with adversarial thinking)
COT_PROCEDURE = """\
Please think step by step and follow the following procedure.
Step 1: Understand the code and identify key instructions and program states.
Step 2: For EACH relevant CWE, think like an attacker: what specific malicious input would you craft to exploit this code? Be concrete (e.g., pass "__proto__" as path, create a symlink at the lock path, supply "CON.txt" as filename).
Step 3: Trace the malicious input through the code. Does ANY code path fail to block it? A missing check IS a vulnerability even if the code works correctly for benign inputs.
Step 4: If the code lacks an explicit defense against a specific attack vector, it IS vulnerable. Do not assume upstream validation exists. Do not dismiss incomplete checks as "not a security flaw". An incomplete mitigation IS a vulnerability.
You should STRICTLY structure your response as follows:"""

# CWE descriptions for policy-guided detection
CWE_DB = {
    # Memory safety
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-787": "Out-of-bounds Write",
    "CWE-416": "Use After Free",
    "CWE-415": "Double Free",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-190": "Integer Overflow or Wraparound",
    # Injection
    "CWE-74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
    # Path traversal / file handling
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-59": "Improper Link Resolution Before File Access ('Link Following')",
    "CWE-67": "Improper Handling of Windows Device Names",
    "CWE-73": "External Control of File Name or Path",
    # Race conditions
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
    "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
    # Auth / access control
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-913": "Improper Control of Dynamically-Managed Code Resources",
    # Input validation
    "CWE-20": "Improper Input Validation",
    "CWE-134": "Use of Externally-Controlled Format String",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
    # HTTP protocol
    "CWE-444": "Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')",
    # Cryptographic
    "CWE-436": "Interpretation Conflict (ASN.1 / Certificate Validation Bypass)",
    # Resource management
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    # Dynamic attribute control
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes ('Class Pollution')",
}

# CWE-specific detection constraints (from VulnLLM-R paper, enhanced)
CWE_CONSTRAINTS = {
    "CWE-22": "Confirm that the code includes checks for path traversal sequences like '../' or absolute paths. Verify that user-controlled paths are sanitized before use in file operations. Check if archive extraction validates member paths against the target directory.",
    "CWE-59": "Check if file operations follow symbolic links without validation. Look for missing O_NOFOLLOW flags in open() calls. Verify that the code checks if a path is a symlink before operating on it. Check if unlink/delete operations could be tricked via symlink replacement.",
    "CWE-67": "Check if Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) are properly detected regardless of file extensions (e.g. 'CON.txt' or 'NUL.anything'), trailing spaces, colons (e.g. 'CON:'), alternate data streams, or Unicode variants. A check that only matches the bare device name without extension is INCOMPLETE and VULNERABLE.",
    "CWE-78": "Look for user-controlled input passed to system(), exec(), popen(), or subprocess without proper escaping or validation.",
    "CWE-94": "Check if untrusted input can reach code execution functions like eval(), exec(), or reflection-based method invocation without sandbox restrictions. In template engines, check if user-controlled iteration or property access can invoke arbitrary methods.",
    "CWE-367": "Look for gaps between security checks and the actual use of a resource. Check if file operations use O_NOFOLLOW to prevent symlink attacks between check and use. In file lock implementations, check if _release() can be exploited: if an attacker replaces the lock file with a symlink AFTER it is opened but BEFORE it is unlinked, the unlink follows the symlink and deletes an arbitrary file.",
    "CWE-362": "Identify shared resources accessed without proper synchronization. Look for race windows between checking a condition and acting on it.",
    "CWE-1321": "Check if object property paths are validated before use with operations like set, unset, merge, or defaultsDeep. Specifically check: can a user pass '__proto__' or 'constructor' as a path segment? If castPath/toKey do NOT filter these reserved keys, the code IS vulnerable to prototype pollution. The absence of a blocklist for __proto__/constructor/prototype means VULNERABLE.",
    "CWE-502": "Check if deserialization functions (pickle.loads, pickle.load, yaml.load, yaml.unsafe_load, ObjectMapper.readValue, readObject, unserialize, marshal.loads) process externally-sourced data. pickle is inherently unsafe for untrusted data even with HMAC signature verification.",
    "CWE-913": "Check if reflection or introspection APIs (Introspector.getBeanInfo, getMethod().invoke()) are used without security restrictions, especially in sandbox/template engine contexts. If getBeanInfo is called on user-controlled objects without filtering dangerous methods (getClass, etc.), it IS vulnerable.",
    "CWE-1336": "Check if template engines allow access to dangerous objects or methods that could lead to code execution or sandbox escape.",
    "CWE-444": "Check if HTTP parsers handle chunked transfer-encoding strictly per RFC 7230. Specifically: does the parser validate that chunk footers are exactly \\r\\n? If any 2 bytes are accepted as the footer (instead of strictly \\r\\n), different parsers will disagree on message boundaries, enabling request smuggling.",
    "CWE-436": "Check if ASN.1 or certificate validation performs tag-class/type checks BEFORE recursing into sub-structures. If optional fields that fail validation still trigger recursive parsing or capture, malformed inputs can be reinterpreted as subsequent mandatory fields, bypassing signature verification.",
    "CWE-915": "Check if object traversal functions (getattr, obj[elem]) validate attribute names before accessing them. Specifically: can a user pass dunder attributes (__globals__, __builtins__, __class__) as path elements? If getattr(obj, elem) is called without checking for __ prefixes, arbitrary Python internals can be accessed/modified (class pollution). Also check if safety sets (SAFE_TO_IMPORT) are mutable (set vs frozenset).",
}

# Code-level relevance patterns: CWE is only relevant if code matches at least ONE pattern.
# CWEs not listed here are always considered relevant (safe default).
# This is a structural filter — prevents running focused analysis for CWEs
# that clearly don't apply (e.g., CWE-22 path traversal on code that does no file I/O).
CWE_CODE_PATTERNS = {
    # Filesystem CWEs — only relevant if code touches the filesystem
    "CWE-22": [
        # Python
        r"\bopen\s*\(", r"\bos\.path\b", r"\bos\.stat\b", r"\bos\.access\b",
        r"\bos\.walk\b", r"\bos\.listdir\b", r"\bshutil\.", r"\bpathlib\b",
        r"\bos\.rename\b", r"\bos\.remove\b", r"\bos\.unlink\b", r"\bos\.makedirs\b",
        r"\btarfile\b",
        # Java
        r"\bZip\w+\b", r"\bFiles\.\w+\b", r"\.resolve\s*\(",
        r"\bnew\s+File\b", r"\bFile\w*Stream\b",
        # JS/Node
        r"\bfs\.\w+\b", r"\.extractall\b", r"\.extract\b",
    ],
    "CWE-59": [
        # Python
        r"\bos\.path\b", r"\bos\.stat\b", r"\bos\.lstat\b", r"\bos\.access\b",
        r"\bos\.unlink\b", r"\bos\.remove\b", r"\bos\.symlink\b", r"\bos\.link\b",
        r"\bopen\s*\(", r"\bshutil\.", r"\bpathlib\b", r"\bos\.rename\b",
        r"\bunlink\s*\(", r"\bsymlink\b",
        # Java
        r"\bFiles\.\w+\b", r"\.resolve\s*\(", r"\bnew\s+File\b",
        # JS/Node
        r"\bfs\.\w+\b",
    ],
    "CWE-67": [
        # Python
        r"\bos\.path\b", r"\bopen\s*\(", r"\bpathlib\b", r"\bos\.stat\b",
        r"\bos\.access\b", r"\bos\.rename\b",
        # Java
        r"\bFiles\.\w+\b", r"\.resolve\s*\(", r"\bnew\s+File\b",
        # JS/Node
        r"\bfs\.\w+\b",
    ],
    "CWE-367": [
        r"\bos\.\w+\b", r"\bopen\s*\(", r"\bpathlib\b", r"\block\b",
        r"\bunlink\b", r"\bos\.remove\b", r"\bstat\s*\(", r"\baccess\s*\(",
        r"\bFiles\.\w+\b", r"\.resolve\s*\(",
    ],
    # Deserialization — only relevant if code deserializes
    "CWE-502": [
        r"\bpickle\b", r"\bunpickle\b", r"\byaml\.load\b", r"\byaml\.unsafe_load\b",
        r"\bObjectMapper\b", r"\breadValue\b", r"\bmarshal\.loads?\b",
        r"\bjsonpickle\b", r"\bshelve\b", r"\bdill\b",
        r"\bunserializ", r"\bdeserializ",
        r"\bObjectInputStream\b", r"\breadObject\b",
    ],
    # SQL injection — only relevant if code does SQL
    "CWE-89": [
        r"\bSELECT\s", r"\bINSERT\s", r"\bUPDATE\s", r"\bDELETE\s",
        r"\bsql\b", r"\bcursor\.\w*execute\b", r"\bquery\s*\(",
    ],
    # Command injection — only relevant if code executes system commands
    "CWE-78": [
        r"\bos\.system\b", r"\bos\.popen\b", r"\bsubprocess\b",
        r"\bshell\s*=\s*True\b", r"\bPopen\b", r"\bsystem\s*\(",
        r"\bRuntime\..*exec\b", r"\bchild_process\b", r"\bexecSync\b",
        r"\bspawn\b",
    ],
    # CWE-1321 (Prototype Pollution) NOT filtered — JS/TS-only via LANGUAGE_CWES
    # and hard to pattern-match (lodash uses castPath/toKey, not literal __proto__).
    # Code injection — only relevant if code has eval/exec/compile or template execution
    "CWE-94": [
        r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\(",
        r"\bnew\s+Function\s*\(", r"\bProcessBuilder\b",
        r"\bReflect\b", r"\bIntrospector\b",
        r"\btemplate\b", r"\brender\b",
    ],
    # Template injection — only relevant if code uses template engines
    "CWE-1336": [
        r"\btemplate\b", r"\brender\b", r"\bTemplate\b", r"\bJinja\b",
        r"\bMustache\b", r"\bHandlebars\b", r"\bFreemarker\b",
        r"\bexec\s*\(", r"\bcompile\s*\(",
    ],
    # Class pollution — only relevant if code does dynamic attribute access
    "CWE-915": [
        r"\bgetattr\s*\(", r"\bsetattr\s*\(", r"__globals__", r"__builtins__",
        r"__class__", r"__import__", r"\battr\b",
    ],
}


def filter_relevant_cwes(code: str, cwe_ids: list[str]) -> list[str]:
    """Filter CWEs to only those relevant to the code based on API/pattern matching.

    CWEs without defined relevance patterns are always included (safe default).
    This prevents false positives from running CWE-22 on string-parsing code, etc.
    """
    relevant = []
    for cwe_id in cwe_ids:
        patterns = CWE_CODE_PATTERNS.get(cwe_id)
        if patterns is None:
            # No patterns defined → always relevant (safe default)
            relevant.append(cwe_id)
            continue
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                relevant.append(cwe_id)
                break
    return relevant


# Language-specific CWE focus sets
LANGUAGE_CWES = {
    "c": ["CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-416", "CWE-415", "CWE-476", "CWE-190", "CWE-134", "CWE-78", "CWE-22", "CWE-362", "CWE-367", "CWE-59"],
    "cpp": ["CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-416", "CWE-415", "CWE-476", "CWE-190", "CWE-134", "CWE-78", "CWE-22", "CWE-362", "CWE-367", "CWE-59"],
    "python": ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-22", "CWE-502", "CWE-200", "CWE-400", "CWE-367", "CWE-362", "CWE-59", "CWE-67", "CWE-20", "CWE-74", "CWE-1336", "CWE-444", "CWE-915"],
    "java": ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-22", "CWE-200", "CWE-284", "CWE-913", "CWE-917", "CWE-1336", "CWE-20", "CWE-74", "CWE-770"],
    "javascript": ["CWE-79", "CWE-94", "CWE-1321", "CWE-78", "CWE-22", "CWE-89", "CWE-200", "CWE-400", "CWE-74", "CWE-20", "CWE-502", "CWE-436"],
    "typescript": ["CWE-79", "CWE-94", "CWE-1321", "CWE-78", "CWE-22", "CWE-89", "CWE-200", "CWE-400", "CWE-74", "CWE-20", "CWE-502", "CWE-436"],
}


def build_user_prompt(code: str, language: str, filename: str, cwe_focus: list[str] | None = None, extra_constraints: str = "") -> str:
    """Build the user prompt matching VulnLLM-R's official format."""

    # CWE policy section
    if cwe_focus:
        policy = "You should only focus on checking and reasoning if the code contains one of the following CWEs, or other CWE if you think it is more relevant:\n"
        for cwe_id in cwe_focus:
            desc = CWE_DB.get(cwe_id, "")
            if desc:
                policy += f"- {cwe_id}: {desc}\n"
    else:
        policy = ""

    # Collect CWE-specific constraints for focused CWEs
    constraint_text = ""
    if cwe_focus:
        constraints = []
        for cwe_id in cwe_focus:
            if cwe_id in CWE_CONSTRAINTS:
                constraints.append(f"- {cwe_id}: {CWE_CONSTRAINTS[cwe_id]}")
        if constraints:
            constraint_text = "- Apply these vulnerability-specific checks:\n" + "\n".join(constraints)

    if extra_constraints:
        constraint_text += "\n" + extra_constraints

    prompt = f"""\
You are an advanced vulnerability detection model. \
Your task is to check if a specific vulnerability exists in a given piece of code. \
You need to output whether the code is vulnerable and the type of vulnerability present with cwe id (CWE-xx).

## You are given the following code snippet from `{filename}` ({language}):
```{language}
{code}
```

{policy}
{COT_PROCEDURE}

## Final Answer
#judge: <yes/no>
#type: <vulnerability type>

## Additional Constraint:
- If `#judge: yes`, then `#type:` **must contain exactly one CWE**.
- If `#judge: yes`, the model must output **only the most probable CWE** related to the given code snippet.
{constraint_text}

## Example
- If the code is vulnerable to a CWE-79, you should finally output:
## Final Answer
#judge: yes
#type: CWE-79

- If the code does not contain vulnerabilities related to the given CWE, you should finally output:
## Final Answer
#judge: no
#type: N/A"""

    return prompt


def build_focused_cwe_prompt(code: str, language: str, filename: str, cwe_id: str) -> str:
    """Build a prompt focused on a SINGLE CWE for deep per-CWE analysis."""
    desc = CWE_DB.get(cwe_id, cwe_id)
    constraint = CWE_CONSTRAINTS.get(cwe_id, "")

    prompt = f"""\
You are an expert security auditor specializing in {cwe_id}: {desc}.
Your ONLY task is to determine if the following code is vulnerable to {cwe_id}.

## Code from `{filename}` ({language}):
```{language}
{code}
```

## Your Analysis Task
Focus EXCLUSIVELY on {cwe_id}. Ignore all other vulnerability types.

Step 1: What specific attack input would exploit {cwe_id} in this code? Be concrete.
Step 2: Trace that attack input through every code path. Does the code block it at every point?
Step 3: If there is ANY code path where the attack succeeds, the code IS vulnerable.

{f"## Detection Rule for {cwe_id}:" if constraint else ""}
{constraint}

IMPORTANT: Do not assume upstream validation exists. Analyze ONLY the code shown.
If the code lacks an explicit defense, it IS vulnerable. An incomplete check IS a vulnerability.

## Final Answer
#judge: <yes/no>
#type: {cwe_id} (if yes) or N/A (if no)"""

    return prompt


def build_critique_prompt(code: str, language: str, filename: str,
                          cwe_id: str, initial_analysis: str) -> str:
    """Build a self-critique prompt that challenges an initial 'not vulnerable' verdict."""
    desc = CWE_DB.get(cwe_id, cwe_id)
    constraint = CWE_CONSTRAINTS.get(cwe_id, "")

    prompt = f"""\
A security researcher analyzed this code and concluded it is NOT vulnerable to {cwe_id}: {desc}.

## Code from `{filename}` ({language}):
```{language}
{code}
```

## The researcher's analysis:
{initial_analysis[:2000]}

## Your Task: Devil's Advocate
You are a red team security expert. Your job is to find flaws in the researcher's reasoning.

1. What attack vectors did the researcher MISS or DISMISS too quickly?
2. Are there edge cases, platform differences, or race conditions the researcher overlooked?
3. Does the code actually block ALL variants of the attack, or just the obvious ones?

{f"## Key detection rule for {cwe_id}:" if constraint else ""}
{constraint}

After your critical review, give your INDEPENDENT verdict:

## Final Answer
#judge: <yes/no>
#type: {cwe_id} (if yes) or N/A (if no)"""

    return prompt


def parse_verdict(response_text: str) -> tuple[str, str]:
    """Parse #judge and #type from the structured response."""
    judge_match = re.search(r"#judge:\s*(yes|no)", response_text, re.IGNORECASE)
    type_match = re.search(r"#type:\s*(CWE-\d+|N/A)", response_text, re.IGNORECASE)

    if judge_match:
        is_vulnerable = judge_match.group(1).lower() == "yes"
        cwe = type_match.group(1).upper() if type_match else "UNKNOWN"
        verdict = "VULNERABLE" if is_vulnerable else "NOT VULNERABLE"
    else:
        # Fallback to free-text parsing
        text_lower = response_text.lower()
        if "vulnerable" in text_lower and "not vulnerable" not in text_lower:
            verdict = "VULNERABLE"
        elif "not vulnerable" in text_lower:
            verdict = "NOT VULNERABLE"
        else:
            verdict = "UNCERTAIN"
        cwe_matches = re.findall(r"CWE-\d+", response_text.upper())
        cwe = cwe_matches[0] if cwe_matches else "N/A"

    return verdict, cwe


@app.cls(
    gpu=GPU_TYPE,
    timeout=600,
    scaledown_window=300,
)
@modal.concurrent(max_inputs=10)
class VulnLLMModel:
    @modal.enter()
    def load_model(self):
        from vllm import LLM, SamplingParams

        self.llm = LLM(
            model=MODEL_ID,
            dtype="bfloat16",
            max_model_len=16384,
            gpu_memory_utilization=0.90,
            trust_remote_code=True,
        )
        self.sampling_params = SamplingParams(
            max_tokens=4096,
            temperature=0.1,
            top_p=0.95,
            stop=["<|im_end|>"],
        )
        # Higher temperature for discovery passes (more diverse hypotheses)
        self.discovery_sampling_params = SamplingParams(
            max_tokens=4096,
            temperature=0.6,
            top_p=0.95,
            stop=["<|im_end|>"],
        )

    def _truncate(self, code: str, max_chars: int = 6000) -> str:
        if len(code) <= max_chars:
            return code
        return code[:max_chars] + "\n// ... truncated ...\n"

    def _run_inference(self, conversations: list[list[dict]], sampling_params=None) -> list[str]:
        """Run vLLM inference on a list of conversations."""
        outputs = self.llm.chat(
            messages=conversations,
            sampling_params=sampling_params or self.sampling_params,
        )
        return [o.outputs[0].text for o in outputs]

    @modal.method()
    def analyze(self, code: str, language: str, filename: str,
                cwe_hints: list[str] | None = None) -> dict:
        """Analyze a single code snippet with CWE-aware prompting."""
        code = self._truncate(code)

        # Use language-specific CWEs + any provided hints
        lang_key = language.lower()
        cwe_focus = list(LANGUAGE_CWES.get(lang_key, LANGUAGE_CWES.get("python", [])))
        if cwe_hints:
            for cwe in cwe_hints:
                if cwe not in cwe_focus:
                    cwe_focus.append(cwe)

        user_prompt = build_user_prompt(code, language, filename, cwe_focus)
        conversation = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        responses = self._run_inference([conversation])
        response_text = responses[0]
        verdict, cwe = parse_verdict(response_text)

        return {
            "filename": filename,
            "language": language,
            "verdict": verdict,
            "detected_cwe": cwe,
            "analysis": response_text,
        }

    @modal.method()
    def analyze_multipass(self, code: str, language: str, filename: str,
                          num_passes: int = 3) -> dict:
        """
        Multi-pass analysis matching VulnLLM-R's multi_run_with_related_cwe strategy.

        Passes 1..N-1: Discovery -- broad scan with higher temperature to collect CWE hypotheses
        Pass N: Enriched -- re-analyze focusing on discovered CWEs with full constraints
        """
        code = self._truncate(code)
        lang_key = language.lower()
        base_cwes = list(LANGUAGE_CWES.get(lang_key, LANGUAGE_CWES.get("python", [])))

        # --- Discovery passes (higher temperature for diverse hypotheses) ---
        collected_cwes = set()
        discovery_verdicts = []
        discovery_conversations = []
        for _ in range(num_passes - 1):
            user_prompt = build_user_prompt(code, language, filename, base_cwes)
            discovery_conversations.append([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ])

        if discovery_conversations:
            discovery_responses = self._run_inference(
                discovery_conversations, self.discovery_sampling_params
            )
            for resp in discovery_responses:
                cwe_matches = re.findall(r"CWE-\d+", resp.upper())
                collected_cwes.update(cwe_matches)
                verdict, _ = parse_verdict(resp)
                discovery_verdicts.append(verdict)

        # --- Enriched final run (low temperature, precise) ---
        enriched_cwes = list(base_cwes)
        for cwe in collected_cwes:
            if cwe not in enriched_cwes:
                enriched_cwes.append(cwe)

        user_prompt = build_user_prompt(code, language, filename, enriched_cwes)
        final_conversation = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        final_responses = self._run_inference([final_conversation])
        response_text = final_responses[0]
        verdict, cwe = parse_verdict(response_text)

        # If any discovery pass found VULNERABLE but final didn't, flag as UNCERTAIN
        if verdict == "NOT VULNERABLE" and "VULNERABLE" in discovery_verdicts:
            verdict = "UNCERTAIN"

        return {
            "filename": filename,
            "language": language,
            "verdict": verdict,
            "detected_cwe": cwe,
            "discovered_cwes": sorted(collected_cwes),
            "analysis": response_text,
        }

    @modal.method()
    def analyze_deep(self, code: str, language: str, filename: str,
                     top_k_cwes: int = 5) -> dict:
        """
        Deep analysis combining per-CWE focused passes + self-critique + any-of-N voting.

        Strategy:
        1. Discovery: 2 broad passes (temp=0.6) to identify candidate CWEs
        2. Per-CWE focused: for top-K candidate CWEs, run a SEPARATE pass
           focused exclusively on that one CWE with its detection constraint
        3. Self-critique: for each CWE where focused pass said "not vulnerable",
           run a devil's-advocate refutation pass
        4. Voting: if ANY pass (discovery, focused, or critique) says VULNERABLE
           for a given CWE, include it in the findings
        """
        code = self._truncate(code)
        lang_key = language.lower()
        base_cwes = list(LANGUAGE_CWES.get(lang_key, LANGUAGE_CWES.get("python", [])))

        # ---- Phase 1: Discovery (broad, high-temp) ----
        discovery_conversations = []
        for _ in range(2):
            user_prompt = build_user_prompt(code, language, filename, base_cwes)
            discovery_conversations.append([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ])

        discovery_responses = self._run_inference(
            discovery_conversations, self.discovery_sampling_params
        )

        # Collect CWE candidates from discovery
        candidate_cwes = set()
        discovery_hits = {}
        for resp in discovery_responses:
            cwe_matches = re.findall(r"CWE-\d+", resp.upper())
            candidate_cwes.update(cwe_matches)
            verdict, det_cwe = parse_verdict(resp)
            if verdict == "VULNERABLE" and det_cwe != "N/A":
                discovery_hits[det_cwe] = resp

        # Also include CWEs that have constraints (most likely to find something)
        for cwe_id in base_cwes:
            if cwe_id in CWE_CONSTRAINTS:
                candidate_cwes.add(cwe_id)

        # Rank by: has constraint > mentioned in discovery > others
        def cwe_priority(cwe):
            score = 0
            if cwe in CWE_CONSTRAINTS:
                score += 2
            if cwe in candidate_cwes:
                score += 1
            if cwe in discovery_hits:
                score += 3
            return -score

        ranked_cwes = sorted(candidate_cwes, key=cwe_priority)[:top_k_cwes]

        # ---- Relevance filter: skip CWEs that don't match code patterns ----
        ranked_cwes = filter_relevant_cwes(code, ranked_cwes)

        # ---- Phase 2: Per-CWE focused analysis ----
        focused_conversations = []
        focused_cwe_ids = []
        for cwe_id in ranked_cwes:
            prompt = build_focused_cwe_prompt(code, language, filename, cwe_id)
            focused_conversations.append([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ])
            focused_cwe_ids.append(cwe_id)

        focused_responses = (
            self._run_inference(focused_conversations) if focused_conversations else []
        )

        # Collect focused results
        focused_results = {}
        critique_needed = []
        for i, resp in enumerate(focused_responses):
            cwe_id = focused_cwe_ids[i]
            verdict, _ = parse_verdict(resp)
            focused_results[cwe_id] = {"verdict": verdict, "analysis": resp}
            if verdict != "VULNERABLE":
                critique_needed.append((cwe_id, resp))

        # ---- Phase 3: Self-critique for "not vulnerable" verdicts ----
        critique_conversations = []
        critique_cwe_ids = []
        for cwe_id, initial_analysis in critique_needed:
            prompt = build_critique_prompt(
                code, language, filename, cwe_id, initial_analysis
            )
            critique_conversations.append([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ])
            critique_cwe_ids.append(cwe_id)

        critique_results = {}
        if critique_conversations:
            critique_responses = self._run_inference(
                critique_conversations, self.discovery_sampling_params
            )
            for i, resp in enumerate(critique_responses):
                cwe_id = critique_cwe_ids[i]
                verdict, _ = parse_verdict(resp)
                critique_results[cwe_id] = {"verdict": verdict, "analysis": resp}

        # ---- Phase 4: Any-of-N voting ----
        # A CWE is flagged if ANY phase found it vulnerable
        # Discovery hits are also filtered for relevance
        relevant_set = set(filter_relevant_cwes(code, list(discovery_hits.keys())))
        flagged_cwes = {}
        # From discovery (only if code-relevant)
        for cwe_id, resp in discovery_hits.items():
            if cwe_id in relevant_set:
                flagged_cwes[cwe_id] = "discovery"
        # From focused
        for cwe_id, result in focused_results.items():
            if result["verdict"] == "VULNERABLE":
                flagged_cwes[cwe_id] = "focused"
        # From critique
        for cwe_id, result in critique_results.items():
            if result["verdict"] == "VULNERABLE":
                flagged_cwes[cwe_id] = "critique"

        # Build final verdict
        if flagged_cwes:
            verdict = "VULNERABLE"
            # Pick the CWE flagged with highest confidence
            # Priority: focused > critique > discovery
            best_cwe = None
            for phase in ["focused", "critique", "discovery"]:
                for cwe_id, source in flagged_cwes.items():
                    if source == phase:
                        best_cwe = cwe_id
                        break
                if best_cwe:
                    break
            detected_cwe = best_cwe or list(flagged_cwes.keys())[0]
        else:
            verdict = "NOT VULNERABLE"
            detected_cwe = "N/A"

        # Build analysis summary
        analysis_parts = []
        if flagged_cwes:
            analysis_parts.append(f"VULNERABLE: {', '.join(flagged_cwes.keys())}")
            for cwe_id, source in flagged_cwes.items():
                analysis_parts.append(f"\n--- {cwe_id} (flagged by {source} pass) ---")
                if source == "focused":
                    analysis_parts.append(focused_results[cwe_id]["analysis"][:500])
                elif source == "critique":
                    analysis_parts.append(critique_results[cwe_id]["analysis"][:500])
                elif cwe_id in discovery_hits:
                    analysis_parts.append(discovery_hits[cwe_id][:500])

        return {
            "filename": filename,
            "language": language,
            "verdict": verdict,
            "detected_cwe": detected_cwe,
            "flagged_cwes": flagged_cwes,
            "candidate_cwes": sorted(candidate_cwes),
            "focused_cwes": focused_cwe_ids,  # after relevance filtering
            "analysis": "\n".join(analysis_parts) if analysis_parts else "No vulnerabilities found.",
        }

    @modal.method()
    def analyze_batch(self, items: list[dict]) -> list[dict]:
        """Analyze multiple code snippets in a batch with CWE-aware prompting."""
        conversations = []
        for item in items:
            code = self._truncate(item['code'])
            lang_key = item['language'].lower()
            cwe_focus = LANGUAGE_CWES.get(lang_key, LANGUAGE_CWES.get("python", []))
            cwe_hints = item.get("cwe_hints")
            if cwe_hints:
                cwe_focus = list(cwe_focus) + [c for c in cwe_hints if c not in cwe_focus]

            user_prompt = build_user_prompt(code, item['language'], item['filename'], cwe_focus)
            conversations.append([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ])

        responses = self._run_inference(conversations)

        results = []
        for i, response_text in enumerate(responses):
            verdict, cwe = parse_verdict(response_text)
            results.append({
                "filename": items[i]["filename"],
                "language": items[i]["language"],
                "verdict": verdict,
                "detected_cwe": cwe,
                "analysis": response_text,
            })

        return results

    @modal.method()
    def health(self) -> dict:
        return {"status": "ok", "model": MODEL_ID, "gpu": GPU_TYPE}


# --- FastAPI web endpoint (authenticated via bearer token) ---

@app.function(
    timeout=600,
    secrets=[modal.Secret.from_name("vulnllm-api-key", required_keys=["API_KEY"])],
)
@modal.concurrent(max_inputs=20)
@modal.asgi_app()
def web_app():
    import os

    from fastapi import Depends, FastAPI, HTTPException
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel

    api = FastAPI(title="VulnLLM Analyzer API", version="2.0.0")
    model = VulnLLMModel()
    security = HTTPBearer()

    EXPECTED_KEY = os.environ["API_KEY"]

    def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
        if credentials.credentials != EXPECTED_KEY:
            raise HTTPException(status_code=401, detail="Invalid API key")

    class AnalyzeRequest(BaseModel):
        code: str
        language: str = "c"
        filename: str = "unknown"
        cwe_hints: list[str] | None = None
        multipass: bool = False
        deep: bool = False

    class BatchAnalyzeRequest(BaseModel):
        items: list[AnalyzeRequest]

    @api.get("/health", dependencies=[Depends(verify_token)])
    async def health():
        return model.health.remote()

    @api.post("/analyze", dependencies=[Depends(verify_token)])
    async def analyze(req: AnalyzeRequest):
        try:
            if req.deep:
                return model.analyze_deep.remote(req.code, req.language, req.filename)
            if req.multipass:
                return model.analyze_multipass.remote(req.code, req.language, req.filename)
            return model.analyze.remote(req.code, req.language, req.filename, req.cwe_hints)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @api.post("/analyze/batch", dependencies=[Depends(verify_token)])
    async def analyze_batch(req: BatchAnalyzeRequest):
        try:
            items = [item.model_dump() for item in req.items]
            return model.analyze_batch.remote(items)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    return api
