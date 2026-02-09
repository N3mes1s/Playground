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
GPU_TYPE = "A100-40GB"  # 40GB VRAM, ample room for 7B model + large context

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

    def _truncate(self, code: str, max_chars: int = 6000) -> str:
        """Truncate code to fit within model context window."""
        if len(code) <= max_chars:
            return code
        return code[:max_chars] + "\n// ... truncated ...\n"

    @modal.method()
    def analyze(self, code: str, language: str, filename: str) -> dict:
        """Analyze a single code snippet for vulnerabilities."""
        from vllm import SamplingParams

        code = self._truncate(code)
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
            code = self._truncate(item['code'])
            user_prompt = (
                f"Analyze the following {item['language']} code from file "
                f"`{item['filename']}` for security vulnerabilities.\n\n"
                f"Code:\n```{item['language']}\n{code}\n```\n\n"
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


# --- FastAPI web endpoint (authenticated via bearer token) ---
#
# To use this endpoint, first create a Modal secret named "vulnllm-api-key":
#     modal secret create vulnllm-api-key API_KEY=<your-chosen-key>
#
# Then pass the key in every request:
#     curl -H "Authorization: Bearer <your-chosen-key>" https://...modal.run/health

@app.function(
    timeout=600,
    secrets=[modal.Secret.from_name("vulnllm-api-key", required_keys=["API_KEY"])],
)
@modal.concurrent(max_inputs=20)
@modal.asgi_app()
def web_app():
    import os

    from fastapi import Depends, FastAPI, HTTPException, Request
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel

    api = FastAPI(title="VulnLLM Analyzer API", version="1.0.0")
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

    class BatchAnalyzeRequest(BaseModel):
        items: list[AnalyzeRequest]

    @api.get("/health", dependencies=[Depends(verify_token)])
    async def health():
        return model.health.remote()

    @api.post("/analyze", dependencies=[Depends(verify_token)])
    async def analyze(req: AnalyzeRequest):
        try:
            return model.analyze.remote(req.code, req.language, req.filename)
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
