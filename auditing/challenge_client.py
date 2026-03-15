from pathlib import Path
import httpx
from .models import Challenge, ChallengeReport
import os




class ChallengeClient:
    def __init__(self):
        self.challenge_api_url = os.getenv("CHALLENGE_API")
        self.challenge_report_api_url = os.getenv("CHALLENGE_REPORT_API")
        
        if not self.challenge_api_url or not self.challenge_report_api_url:
            raise EnvironmentError("Challenge API URLs must be set in the environment variables.")

    async def fetch_random_challenge(self) -> Challenge:
        async with httpx.AsyncClient() as client:
            response = await client.get(self.challenge_api_url + "/random")
            response.raise_for_status()
            return Challenge.model_validate(response.json())

    async def fetch_report(self, project_id: str) -> ChallengeReport:
        async with httpx.AsyncClient() as client:
            response = await client.get(self.challenge_report_api_url + f"/{project_id}")
            response.raise_for_status()
            return ChallengeReport.model_validate(response.json())

    async def fetch_all_challenges(self) -> list[Challenge]:
        async with httpx.AsyncClient() as client:
            response = await client.get(self.challenge_api_url + "/all")
            response.raise_for_status()
        return [Challenge.model_validate(challenge) for challenge in response.json()]