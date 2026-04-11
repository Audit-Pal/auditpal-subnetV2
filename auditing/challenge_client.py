from pathlib import Path
import httpx
from .models import Challenge, ChallengeReport
import os
import asyncio


class ChallengeClient:
    def __init__(self):
        self.challenge_api_url = os.getenv("CHALLENGE_API")
        self.challenge_report_api_url = os.getenv("CHALLENGE_REPORT_API")

        if not self.challenge_api_url or not self.challenge_report_api_url:
            raise EnvironmentError("Challenge API URLs must be set in environment variables.")

        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0)
        )

    async def _get_with_retry(self, url: str, retries: int = 3):
        for attempt in range(retries):
            try:
                response = await self.client.get(url)
                response.raise_for_status()
                return response
            except httpx.ReadTimeout:
                if attempt == retries - 1:
                    raise
                await asyncio.sleep(2 ** attempt)  # exponential backoff

    async def fetch_random_challenge(self) -> Challenge:
        response = await self._get_with_retry(self.challenge_api_url + "/random")
        return Challenge.model_validate(response.json())

    async def fetch_report(self, project_id: str) -> ChallengeReport:
        response = await self._get_with_retry(
            self.challenge_report_api_url + f"/{project_id}"
        )
        return ChallengeReport.model_validate(response.json())

    async def fetch_all_challenges(self) -> list[Challenge]:
        response = await self._get_with_retry(self.challenge_api_url + "/all")
        return [Challenge.model_validate(ch) for ch in response.json()]

    async def close(self):
        await self.client.aclose()