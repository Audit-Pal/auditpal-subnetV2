import time
import bittensor as bt
from pathlib import Path
from template.protocol import AuditSynapse
from template.validator.reward import get_rewards
from template.utils.uids import get_random_uids
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env.validator")

# Import AFTER load_dotenv
from auditing.challenge_client import ChallengeClient
challenge_client = ChallengeClient()

async def forward(self):
    challenge = await challenge_client.fetch_random_challenge()
    
    synapse = AuditSynapse(
        challenge_json=challenge.model_dump_json(by_alias=True)
    )

    miner_uids = get_random_uids(self, k=self.config.neuron.sample_size)

    responses = await self.dendrite(
        axons=[self.metagraph.axons[uid] for uid in miner_uids],
        synapse=AuditSynapse(AuditSynapse_input=self.step),
        deserialize=True,
        timeout=self.config.neuron.timeout,
    )

    bt.logging.info(f"Received responses: {responses}")

    rewards = get_rewards(self, query=self.step, responses=responses)

    bt.logging.info(f"Scored responses: {rewards}")
    self.update_scores(rewards, miner_uids)
    time.sleep(5)