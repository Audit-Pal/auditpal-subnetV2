from .models import Challenge, ChallengeReport
import requests
import dotenv
class ChallengeClient:
    def __init__(self):
        pass
    
    def fetch_random_challenge(self) -> Challenge:
        response = requests.get(dotenv.get("CHALLENGE_API_URL") + "/random")
        response.raise_for_status()
        return Challenge.model_validate(response.json())
    
    def fetch_report(self, project_id: str) -> ChallengeReport:
        response = requests.get(dotenv.get("CHALLENGE_REPORT_API_URL") + f"/{project_id}")
        response.raise_for_status()
        return ChallengeReport.model_validate(response.json())
    
    
    def fetch_all_challenges(self) -> list[Challenge]:
        response = requests.get(dotenv.get("CHALLENGE_API_URL") + "/all")
        response.raise_for_status()
        return [Challenge.model_validate(challenge) for challenge in response.json()]