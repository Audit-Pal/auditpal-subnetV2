import os
import logging

log = logging.getLogger(__name__)


class LLMClient:
    def __init__(self, role: str = "default"):
        self.role = role

        # Priority:
        # 1. ROLE_PROVIDER (e.g. ANALYZER_PROVIDER)
        # 2. LLM_PROVIDER
        self.provider = (
            os.getenv(f"{role.upper()}_PROVIDER")
            or os.getenv("LLM_PROVIDER", "gemini")
        )

        log.info(f"[LLM] Provider={self.provider} role={role}")

        self._init_provider()

    # ---------------- INIT ----------------

    def _init_provider(self):
        if self.provider == "gemini":
            self._init_gemini()

        elif self.provider == "openai":
            self._init_openai()

        elif self.provider == "anthropic":
            self._init_anthropic()

        elif self.provider == "ollama":
            self._init_ollama()

        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")

    # ---------------- PROVIDERS ----------------

    def _init_gemini(self):
        import google.generativeai as genai

        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("Missing GEMINI_API_KEY")

        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        )

    def _init_openai(self):
        from openai import OpenAI

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("Missing OPENAI_API_KEY")

        self.client = OpenAI(api_key=api_key)
        self.model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    def _init_anthropic(self):
        from anthropic import Anthropic

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("Missing ANTHROPIC_API_KEY")

        self.client = Anthropic(api_key=api_key)
        self.model_name = os.getenv("ANTHROPIC_MODEL", "claude-3-haiku-20240307")

    def _init_ollama(self):
        import requests

        self.base_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.model_name = os.getenv("OLLAMA_MODEL", "llama3")

    # ---------------- GENERATE ----------------

    def generate(self, prompt: str) -> str:
        try:
            if self.provider == "gemini":
                return self.model.generate_content(prompt).text or ""

            elif self.provider == "openai":
                res = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[{"role": "user", "content": prompt}],
                )
                return res.choices[0].message.content or ""

            elif self.provider == "anthropic":
                res = self.client.messages.create(
                    model=self.model_name,
                    max_tokens=1024,
                    messages=[{"role": "user", "content": prompt}],
                )
                return res.content[0].text

            elif self.provider == "ollama":
                import requests
                r = requests.post(
                    f"{self.base_url}/api/generate",
                    json={"model": self.model_name, "prompt": prompt},
                    timeout=60,
                )
                return r.json().get("response", "")

        except Exception as e:
            log.error(f"[LLM ERROR] {e}")
            return f"LLM error: {e}"