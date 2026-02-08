"""
Modal GPU service for VulnLLM-R-7B vulnerability analysis.

Deploys the UCSB-SURFI/VulnLLM-R-7B model on Modal with GPU acceleration
using vLLM for fast inference.

Usage:
    # Deploy the service (creates a persistent endpoint):
    modal deploy modal_service.py

    # Run ephemerally for testing:
    modal serve modal_service.py
"""

import modal

MODEL_ID = "UCSB-SURFI/VulnLLM-R-7B"
GPU_TYPE = "A10G"  # Good balance of cost/performance for 7B model

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "vllm==0.8.2",
        "torch",
        "transformers",
        "huggingface_hub",
        "fastapi[standard]",
    )
)

app = modal.App("vulnllm-analyzer", image=image)

SYSTEM_PROMPT = """\
You are VulnLLM-R, an advanced vulnerability detection model specialized in \
analyzing source code for security vulnerabilities. Analyze the provided code \
step-by-step using chain-of-thought reasoning.

For each code snippet:
1. Identify what the code does
2. Analyze potential vulnerability patterns (buffer overflows, injection, \
authentication issues, etc.)
3. Reference relevant CWE identifiers when applicable
4. Provide a clear verdict: VULNERABLE or NOT VULNERABLE
5. If vulnerable, explain the risk and suggest a fix

Be thorough but concise in your reasoning."""


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
            max_model_len=8192,
            gpu_memory_utilization=0.90,
            trust_remote_code=True,
        )
        self.sampling_params = SamplingParams(
            max_tokens=4096,
            temperature=0.1,
            top_p=0.95,
            stop=["<|im_end|>"],
        )

    @modal.method()
    def analyze(self, code: str, language: str, filename: str) -> dict:
        """Analyze a single code snippet for vulnerabilities."""
        from vllm import SamplingParams

        user_prompt = (
            f"Analyze the following {language} code from file `{filename}` "
            f"for security vulnerabilities.\n\nCode:\n```{language}\n{code}\n```\n\n"
            "Please provide your step-by-step reasoning followed by your final verdict."
        )

        conversation = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

        outputs = self.llm.chat(
            messages=[conversation],
            sampling_params=self.sampling_params,
        )

        response_text = outputs[0].outputs[0].text

        # Parse verdict from response
        text_lower = response_text.lower()
        if "vulnerable" in text_lower and "not vulnerable" not in text_lower:
            verdict = "VULNERABLE"
        elif "not vulnerable" in text_lower:
            verdict = "NOT VULNERABLE"
        else:
            verdict = "UNCERTAIN"

        return {
            "filename": filename,
            "language": language,
            "verdict": verdict,
            "analysis": response_text,
        }

    @modal.method()
    def analyze_batch(self, items: list[dict]) -> list[dict]:
        """Analyze multiple code snippets in a batch for throughput."""
        from vllm import SamplingParams

        conversations = []
        for item in items:
            user_prompt = (
                f"Analyze the following {item['language']} code from file "
                f"`{item['filename']}` for security vulnerabilities.\n\n"
                f"Code:\n```{item['language']}\n{item['code']}\n```\n\n"
                "Please provide your step-by-step reasoning followed by your final verdict."
            )
            conversations.append([
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ])

        outputs = self.llm.chat(
            messages=conversations,
            sampling_params=self.sampling_params,
        )

        results = []
        for i, output in enumerate(outputs):
            response_text = output.outputs[0].text
            text_lower = response_text.lower()

            if "vulnerable" in text_lower and "not vulnerable" not in text_lower:
                verdict = "VULNERABLE"
            elif "not vulnerable" in text_lower:
                verdict = "NOT VULNERABLE"
            else:
                verdict = "UNCERTAIN"

            results.append({
                "filename": items[i]["filename"],
                "language": items[i]["language"],
                "verdict": verdict,
                "analysis": response_text,
            })

        return results

    @modal.method()
    def health(self) -> dict:
        return {"status": "ok", "model": MODEL_ID, "gpu": GPU_TYPE}


# --- FastAPI web endpoint (alternative to direct Modal method calls) ---

@app.function(timeout=600)
@modal.concurrent(max_inputs=20)
@modal.asgi_app()
def web_app():
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel

    api = FastAPI(title="VulnLLM Analyzer API", version="1.0.0")
    model = VulnLLMModel()

    class AnalyzeRequest(BaseModel):
        code: str
        language: str = "c"
        filename: str = "unknown"

    class BatchAnalyzeRequest(BaseModel):
        items: list[AnalyzeRequest]

    @api.get("/health")
    async def health():
        return model.health.remote()

    @api.post("/analyze")
    async def analyze(req: AnalyzeRequest):
        try:
            return model.analyze.remote(req.code, req.language, req.filename)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @api.post("/analyze/batch")
    async def analyze_batch(req: BatchAnalyzeRequest):
        try:
            items = [item.model_dump() for item in req.items]
            return model.analyze_batch.remote(items)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    return api
