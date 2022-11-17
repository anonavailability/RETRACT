# Author: Anon

import attr
from retract.utils import (
    make_generators,
    random,
    wsum,
)
from retract.primitives.schnorr import SchnorrCommitment
from py_ecc.bn128 import (
    multiply,
    add,
    neg,
    pairing,
    eq,
    G1,
    G2,
    curve_order,
)

# Prototype implementation of BBS+ signatures from "Anonymous attestation using the strong diffie hellman assumption revisited"

def BBSPlusKeyGen(L):
    ick = make_generators(G1, L + 2)
    isk = random()
    ipk = multiply(G2, isk)
    return (ick, ipk, isk)

def BBSPlusSign(isk, ick, tpk, attrs):
    e = random()
    s = random()
    # (g1 + ick_0*s + tpk + \sum_{i=1}^{L}(ick_{i+1}*a_i))*(1/(e+isk))
    prod = wsum([G1, ick[0], tpk] + ick[2:], 
        [1, s, 1] + attrs)
    A = multiply(prod, pow(e+isk, -1, curve_order)) # compute modular multiplicative inverse
    return (A, e, s)

def BBSPlusVerify(ipk, ick, tpk, attrs, sig):
    (A, e, s) = sig
    # g1 + ick_0*s + tpk + \sum_{i=1}^{L}(ick_{i+1}*a_i)
    prod = wsum([G1, ick[0], tpk] + ick[2:], 
        [1, s, 1] + attrs)
    # e(A, ipk + g2*e) = e(prod, g2)
    return eq(pairing(add(ipk, multiply(G2, e)), A), pairing(G2, prod))

class PoKOfSignatureG1Protocol:
    
    # Following is the 1st step of the Schnorr protocol for the relation pi in the paper, which
    # is a conjunction of 2 relations:
    # 1. `A_bar - d == A'*-e + ick_0*r2`
    # 2. `g1 + \sum_{i \in D}(ick_{i+1}*a_i) == d*r3 + ick_0*-s' + ick_1*-tsk + \sum_{i \notin D}(ick_{i+1}*-a_i)`
    def __init__(self, ipk, ick, tpk, tsk, attrs, revealed_indices, blindings, sig, simulated_challenge=None):
        self.ipk = ipk
        self.ick = ick
        self.revealed_attrs = [attrs[idx] for idx in revealed_indices]
        self.simulated_challenge = simulated_challenge

        (A, e, s) = sig

        # Generate any blindings that aren't explicitly passed
        for idx, m in enumerate(attrs):
            if idx not in revealed_indices and blindings.get(idx) is None:
                blindings[idx] = random()

        r1, r2 = random(), random()
        r3 = pow(r1, -1, curve_order) # compute modular multiplicative inverse

        # b = g1 + ick_0*s + tpk + \sum_{i=1}^{L}(ick_{i+1}*a_i)
        b = wsum([G1, ick[0], tpk] + ick[2:], 
            [1, s, 1] + attrs)
        # A' = A*r1
        self.A_prime = multiply(A, r1)
        # A_bar = A'*-e + b*r1
        self.A_bar = add(neg(multiply(self.A_prime, e)), multiply(b, r1))
        # d = b*r1 + ick_0*-r2
        self.d = add(multiply(b, r1), neg(multiply(ick[0], r2)))
        # s' = s - r2*r3
        s_prime = s - r2 * r3

        # 1st relation: `A_bar - d == A'*-e + ick_0*r2`
        bases_1     = [self.A_prime, ick[0]]
        blindings_1 = [random(), random()]
        self.witnesses_1 = [-e, r2]
        if simulated_challenge:
            bases_1.extend([add(self.A_bar, neg(self.d))]) # lhs = A_bar - d
            blindings_1.extend([simulated_challenge])
            self.sc_comm_1 = SchnorrCommitment.new(bases_1, blindings_1, True)
        else:
            self.sc_comm_1 = SchnorrCommitment.new(bases_1, blindings_1)

        # 2nd relation: `g1 + \sum_{i \in D}(ick_{i+1}*a_i) == d*r3 + ick_0*-s' + ick_1*-tsk + \sum_{i \notin D}(ick_{i+1}*-a_i)`
        bases_2     = [self.d, ick[0], ick[1]]
        blindings_2 = [random(), random(), random()]
        self.witnesses_2 = [r3, -s_prime, -tsk]
        # Capture all unrevealed attributes
        for idx, a in enumerate(attrs):
            if idx not in revealed_indices:
                bases_2.append(ick[idx+2])
                blindings_2.append(blindings.get(idx))
                self.witnesses_2.append(-a)

        if simulated_challenge:
            bases_revealed = []
            exponents = []
            for idx in revealed_indices:
                bases_revealed.append(ick[idx+2])
                exponents.append(attrs[idx])

            bases_2.extend([add(G1, wsum(bases_revealed, exponents))]) # lhs = g1 + \sum_{i \in D}(ick_{i+1}*a_i)
            blindings_2.extend([simulated_challenge])
            self.sc_comm_2 = SchnorrCommitment.new(bases_2, blindings_2, True)
        else:
            self.sc_comm_2 = SchnorrCommitment.new(bases_2, blindings_2)

        print()
        print("t1", self.sc_comm_1.t, "t2", self.sc_comm_2.t, sep="\n")

    def challenge_contribution(self):
        tmp = [self.A_bar]
        # 1st Schnorr
        tmp.extend([self.sc_comm_1.t, self.A_prime, add(self.A_bar, neg(self.d))])
        # 2nd Schnorr
        tmp.extend([self.sc_comm_2.t, G1, self.d])
        tmp.extend(self.ick)
        tmp.extend(self.ipk)
        tmp.extend(self.revealed_attrs)
        return tmp

    def gen_proof(self, challenge=None):
        # Schnorr responses for the two relations: 
        # 1. `A_bar - d == A'*-e + ick_0*r2`
        # 2. `g1 + \sum_{i \in D}(ick_{i+1}*a_i) == d*r3 + ick_0*-s' + ick_1*-tsk + \sum_{i \notin D}(ick_{i+1}*-a_i)`
        if self.simulated_challenge:
            resp_1 = self.sc_comm_1.response()
            resp_2 = self.sc_comm_2.response()
        else:
            resp_1 = self.sc_comm_1.response(self.witnesses_1, challenge)
            resp_2 = self.sc_comm_2.response(self.witnesses_2, challenge)

        return PoKOfSignatureG1Proof(A_prime=self.A_prime, A_bar=self.A_bar, d=self.d, sc_resp_1=resp_1, sc_resp_2=resp_2)

@attr.s
class PoKOfSignatureG1Proof:
    A_prime = attr.ib()
    A_bar = attr.ib()
    d = attr.ib()
    sc_resp_1 = attr.ib()
    sc_resp_2 = attr.ib()

    def verify_signature(self, revealed_attrs, challenge, ipk, ick, L):
        if not eq(pairing(ipk, self.A_prime), pairing(G2, self.A_bar)):
            return False

        # compute t1' for 1st Schnorr proof (relation `A_bar - d == A'*-e + ick_0*r2`)
        bases_1 = [self.A_prime, ick[0]]
        # lhs = A_bar - d
        lhs = add(self.A_bar, neg(self.d))
        # t1_prime = A_prime*s_0 + ick_0*s_1 + lhs*challenge
        self.t1_prime = self.sc_resp_1.t_prime(bases_1, lhs, challenge)

        # compute t2' for 2nd Schnorr proof (relation `g1 + \sum_{i \in D}(ick_{i+1}*a_i) == d*r3 + ick_0*-s' + ick_1*-tsk + \sum_{i \notin D}(ick_{i+1}*-a_i)`)
        bases_2 = [self.d, ick[0], ick[1]]
        bases_revealed = []
        exponents = []

        for idx in range(0, L):
            if idx in revealed_attrs:
                bases_revealed.append(ick[idx+2])
                exponents.append(revealed_attrs.get(idx))
            else:
                bases_2.append(ick[idx+2])
        
        # lhs = g1 + \sum_{i \in D}(ick_{i+1}*a_i)
        lhs = add(G1, wsum(bases_revealed, exponents))
        # t2_prime = d*s_0 + ick_0*s_1 + ick_1*s_2 + \sum_{i not in D}(ick_{i+1}*s_j) + lhs*challenge
        self.t2_prime = self.sc_resp_2.t_prime(bases_2, lhs, challenge)

        print()
        print("t1_prime", self.t1_prime, "t2_prime", self.t2_prime, sep="\n")

        return True

    # For the verifier to independently calculate the challenge
    def challenge_contribution(self, revealed_attrs, ipk, ick):
        tmp = [self.A_bar]
        # 1st Schnorr
        tmp.extend([self.t1_prime, self.A_prime, add(self.A_bar, neg(self.d))])
        # 2nd Schnorr
        tmp.extend([self.t2_prime, G1, self.d])
        tmp.extend(ick)
        tmp.extend(ipk)
        tmp.extend(revealed_attrs)
        return tmp
