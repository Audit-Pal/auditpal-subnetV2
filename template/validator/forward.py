import time
from pathlib import Path

import bittensor as bt
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env.validator")

from template.protocol import AuditSynapse
from template.validator.reward import get_rewards
from template.utils.uids import get_random_uids
from auditing.challenge_client import ChallengeClient
from auditing.sandbox import SandboxRunner

challenge_client = ChallengeClient()
sandbox          = SandboxRunner()


async def forward(self):
    challenge = await challenge_client.fetch_random_challenge()
    ground_truth = await challenge_client.fetch_report(challenge.project_id)
    miner_uids = get_random_uids(self, k=self.config.neuron.sample_size)

    responses = await self.dendrite(
        axons=[self.metagraph.axons[uid] for uid in miner_uids],
        synapse=AuditSynapse(
            challenge_json=challenge.model_dump_json(by_alias=True)
        ),
        deserialize=True,
        timeout=self.config.neuron.timeout,
    )

    bt.logging.info(f"Received responses: {responses}")

    reports = await sandbox.run_all(
        repo_urls=responses,
        challenge=challenge,
    )

    bt.logging.info(f"Reports: {[r is not None for r in reports]}")

    rewards = get_rewards(self, reports=reports, ground_truth=ground_truth)

    bt.logging.info(f"Scored responses: {rewards}")
    self.update_scores(rewards, miner_uids)