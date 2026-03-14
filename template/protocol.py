# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# TODO(developer): Set your name
# Copyright © 2023 <your name>

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import typing
import bittensor as bt

from pydantic import Field
from auditing.models import Codebase 
# TODO(developer): Rewrite with your protocol definition.

# This is the protocol for the AuditSynapse miner and validator.
# It is a simple request-response protocol where the validator sends a request
# to the miner, and the miner responds with a AuditSynapse response.

# ---- miner ----
# Example usage:
#   def AuditSynapse( synapse: AuditSynapse ) -> AuditSynapse:
#       synapse.AuditSynapse_output = synapse.AuditSynapse_input + 1
#       return synapse
#   axon = bt.axon().attach( AuditSynapse ).serve(netuid=...).start()

# ---- validator ---
# Example usage:
#   dendrite = bt.dendrite()
#   AuditSynapse_output = dendrite.query( AuditSynapse( AuditSynapse_input = 1 ) )
#   assert AuditSynapse_output == 2


class AuditSynapse(bt.Synapse):
    """
    A simple AuditSynapse protocol representation which uses bt.Synapse as its base.
    This protocol helps in handling AuditSynapse request and response communication between
    the miner and the validator.

    Attributes:
    - AuditSynapse_input: An integer value representing the input request sent by the validator.
    - AuditSynapse_output: An optional integer value which, when filled, represents the response from the miner.
    """

    challenge_id: str = ""
    project_id: str = ""
    challenge_name: str = ""
    codebases: list[Codebase] = Field(default_factory=list)
   
    report_json: typing.Optional[str] = None

    def deserialize(self) -> int:
        """
        Deserialize the AuditSynapse output. This method retrieves the response from
        the miner in the form of AuditSynapse_output, deserializes it and returns it
        as the output of the dendrite.query() call.

        Returns:
        - int: The deserialized response, which in this case is the value of AuditSynapse_output.

        Example:
        Assuming a AuditSynapse instance has a AuditSynapse_output value of 5:
        >>> AuditSynapse_instance = AuditSynapse(AuditSynapse_input=4)
        >>> AuditSynapse_instance.AuditSynapse_output = 5
        >>> AuditSynapse_instance.deserialize()
        5
        """
        return self.AuditSynapse_output
