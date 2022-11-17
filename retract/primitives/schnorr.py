# Author: Anon

import attr
from retract.utils import (
    wsum,
)
from py_ecc.bn128 import (
    curve_order,
    add,
    multiply,
)

@attr.s
class SchnorrCommitment:
    t = attr.ib()
    blindings = attr.ib()
    cheat = attr.ib()

    @staticmethod
    def new(bases, blindings, cheat=False):
        # Create commitment as `bases[0] * blindings[0] + bases[1] * blindings[1] + ... + bases[i] * blindings[i]`
        # When cheating, the last base (y) and blinding (w) are not included in the response
        t = wsum(bases, blindings)
        return SchnorrCommitment(t=t, blindings=blindings, cheat=cheat)

    def response(self, witnesses=None, challenge=None):
        # Create responses for each witness (discrete log) as `response[i] = self.blindings[i] - (witnesses[i] * challenge)`
        responses = []
        if self.cheat:
            for blinding in self.blindings[:-1]:
                responses.append(blinding % curve_order)
        else:
            for blinding,witness in zip(self.blindings, witnesses):
                resp = (blinding - ((witness * challenge) % curve_order)) % curve_order
                responses.append(resp)
        return SchnorrResponse(responses=responses)

@attr.s
class SchnorrResponse:
    responses = attr.ib()

    def t_prime(self, bases, y, challenge):
        return add(wsum(bases, self.responses), multiply(y, challenge))

    def get_response(self, idx):
        return self.responses[idx]
