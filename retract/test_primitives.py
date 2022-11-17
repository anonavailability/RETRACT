# Author: Anon

from retract.utils import *
from retract.primitives.bbsplus import *
from retract.utils import (
    random,
    compute_challenge,
    exec_and_measure_elapsed,
    wsum,
    make_generators,
)
from py_ecc.bn128 import (
    curve_order,
    eq,
    G1,
    multiply,
    add,
)
from py_ecc.fields import (
    bn128_FQ,
)
from poseidon.poseidon_hash import (
    poseidon_hash,
    p,
)
import subprocess

def run_LegoGro16(circuit_name):
    cmd = ['/app/libsnark-lego/build/libsnark/jsnark_lego_interface/run_lego', 'gg', \
        '/app/retract/%s.arith' %circuit_name,
        '/app/retract/%s_Sample_Run1.in' %circuit_name
    ]
    output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return output.stdout,output.stderr

def test_designated_verifier_poseidon_trapdoor():
    circuit_name = 'trapdoor_poseidon_arity_2'
    inputs = {
        0: 1,
        2: '292a356a754c08f57137725c13ed807f532913300810f2be930ec5881fd6cb86', # image
        3: '99cad489a852618f69445635d4ce6e612257ccc23d70f837806071a47c54a21', # preimage[0]
        4: '180c5ab10e890e75d8ce751065ac9fb17e5907c0bdeb212e394dc33de8db61c0' # preimage[1]
    }
    # Uncomment the below code to test against a fresh secret key
    # sk = random() % p
    # blinding = random() % p
    # blinded_image = poseidon_hash([sk, blinding])
    # inputs[2] = format(blinded_image, 'x')
    # inputs[3] = format(sk, 'x')
    # inputs[4] = format(blinding, 'x')
    with open('%s_Sample_Run1.in'%circuit_name, 'w') as out:
        for input in inputs:
            out.write('%s %s\n' %(input, inputs[input]))
    
    stdout, stderr = run_LegoGro16(circuit_name)

    ck = [] # LegoSNARK commitment key
    opn = [] # blindings (openings) used for LegoSNARK witness commitment
    omega = []
    lego_cm = None # Pedersen commitment
    legosnark_verification_result = False

    for line in stdout.split('\n'):
        print(line) # comment this line to suppress verbose stats
        if 'ck[' in line:
            tmp = line.split('] = ')[1].replace('(', '').replace(')', '')
            X,Y = tmp.split(',')
            ck.append((bn128_FQ(int(X)), bn128_FQ(int(Y))))
        if 'opn[' in line:
            opn.append(int(line.split('] = ')[1]))
        if 'omega[' in line:
            omega.append(int(line.split('] = ')[1]))
        if 'commitment =' in line:
            tmp = line.split('=')[1].replace('(', '').replace(')', '')
            X,Y = tmp.split(',')
            lego_cm = (bn128_FQ(int(X)), bn128_FQ(int(Y)))
        if 'The verification result is:' in line:
            result = line.split('The verification result is:')[1].replace(' ', '')
            if result == 'PASS':
                legosnark_verification_result = True

    cm_prime = wsum(ck, opn)

    # print("openings:", opn)
    # print("omega:", omega)
    # print("lego_cm:", lego_cm)
    # print("legosnark_verification_result:", legosnark_verification_result)
    # print("cm_prime:", cm_prime)

    assert legosnark_verification_result and eq(cm_prime, lego_cm)

def test_bbsplus():
    L = 3
    attrs = [30, 31, 32]

    # issuer
    (ick, ipk, isk) = BBSPlusKeyGen(L)

    # holder's secure element's keypair
    tsk = random()
    tpk = multiply(ick[1], tsk)

    # issuer
    sig = BBSPlusSign(isk, ick, tpk, attrs)
    sigOk = BBSPlusVerify(ipk, ick, tpk, attrs, sig)
    assert sigOk

    # prover
    revealed_indices = [1,2]
    blindings = {0:2}
    revealed_attrs = {1: 31, 2: 32}

    p1 = PoKOfSignatureG1Protocol(ipk, ick, tpk, tsk, attrs, revealed_indices, blindings, sig)
    contribution = p1.challenge_contribution()
    c = compute_challenge(contribution) % curve_order
    proof = p1.gen_proof(c)
    # prover sends verifier: (proof, c, revealed_attrs)

    # verifier
    sigOk = proof.verify_signature(revealed_attrs, c, ipk, ick, L)
    contribution = proof.challenge_contribution(revealed_attrs.values(), ipk, ick)
    c_prime = compute_challenge(contribution) % curve_order

    assert sigOk and c == c_prime

def test_raw_prototype_holder_proof():
    ### HOLDER ###
    L = 4
    attrs = [30, 31, 32, 429]


    ### ISSUER ###
    (ick, ipk, isk) = BBSPlusKeyGen(L)


    ### SECURE ELEMENT ###
    tsk = random()
    tpk = multiply(ick[1], tsk)


    ### ISSUER ###
    sig = BBSPlusSign(isk, ick, tpk, attrs)


    ### VERIFIER ###
    g = make_generators(G1, 1)[0]
    dvsk = random()
    dvpk = multiply(g, dvsk)
    n = random()
    D = [1, 2] # disclosed attribute indices
    I = [4] # undisclosed attribute indices to pass to circuit
    W = len(I)
    ck = make_generators(G1, W+1) # circuit's commitment key (final generator is for opening in Pedersen commitment)


    ### HOLDER ###
    D_bar = [3, 4] # undisclosed attribute indices

    sigOk = BBSPlusVerify(ipk, ick, tpk, attrs, sig)
    assert sigOk

    (A, e, s) = sig

    """ Generate cc-zkSNARK proof over attributes """
    u = [attrs[i-1] for i in I]
    o = random() # opening (blinding)
    t_u = wsum(ck, u + [o]) # Pedersen commitment of the circuit's witnesses

    """ Randomize BBS+ credential """
    r_1, r_2 = random(), random()
    r_3 = pow(r_1, -1, curve_order)

    # b = g1 + ick_0*s + tpk + \sum_{i=1}^{L}(ick_{i+1}*a_i)
    b = wsum([G1, ick[0], tpk] + ick[2:], 
        [1, s, 1] + attrs)
    # A' = A*r_1
    A_prime = multiply(A, r_1)
    # A_bar = A'*-e + b*r_1
    A_bar = add(neg(multiply(A_prime, e)), multiply(b, r_1))
    # d = b*r_1 + ick_0*-r_2
    d = add(multiply(b, r_1), neg(multiply(ick[0], r_2)))
    # s' = s - r_2*r_3
    s_prime = s - r_2 * r_3

    """ Schnorr PoK of discrete logarithm """
    r_a_3, r_a_4 = random(), random()
    r_e, r_r_2, r_r_3, r_s_prime, r_o, r_dvsk, c_2 = random(), random(), random(), random(), random(), random(), random()


    ### SECURE ELEMENT ###
    r_tsk = random()
    t_tsk = multiply(ick[1], r_tsk)


    ### HOLDER ###
    # 1st relation: `A_bar - d == A'*-e + ick_0*r2`
    t_1 = wsum([A_prime, ick[0]], [r_e, r_r_2])

    # 2nd relation: `g1 + \sum_{i \in D}(ick_{i+1}*a_i) == d*r3 + ick_0*-s' + ick_1*-tsk + \sum_{i \notin D}(ick_{i+1}*-a_i)`
    t_2 = wsum([d, ick[0], t_tsk, ick[D_bar[0]+1], ick[D_bar[1]+1]], [r_r_3, r_s_prime, 1, r_a_3, r_a_4])

    # 3rd relation: t_u == \sum_i^{W-1}\sum_{j \in I}(ck_i*a_j) + ck_W*o
    t_3 = wsum(ck, [r_a_4, r_o])

    # 4th relation: dvpk == g*dvsk (here the holder cheats since it doesn't know dvsk)
    t_4 = wsum([g, dvpk], [r_dvsk, c_2])

    c = compute_challenge([n, A_prime, A_bar, d, t_1, t_2, t_3, t_4, G1, D, I, ck, ick, ipk]) % curve_order

    c_1 = (c - c_2) % curve_order

    ### SECURE ELEMENT ###
    s_tsk = (r_tsk + ((c_1 * tsk) % curve_order)) % curve_order

    ### HOLDER ###
    s_a_3     = (r_a_3     + ((c_1 * attrs[D_bar[0]-1]) % curve_order)) % curve_order
    s_a_4     = (r_a_4     + ((c_1 * attrs[D_bar[1]-1]) % curve_order)) % curve_order
    s_e       = (r_e       + ((c_1 * e) % curve_order)) % curve_order
    s_r_2     = (r_r_2     - ((c_1 * r_2) % curve_order)) % curve_order
    s_r_3     = (r_r_3     - ((c_1 * r_3) % curve_order)) % curve_order
    s_s_prime = (r_s_prime + ((c_1 * s_prime) % curve_order)) % curve_order
    s_o       = (r_o       + ((c_1 * o) % curve_order)) % curve_order
    s_r_dvsk  = r_dvsk # (here the holder cheats since it doesn't know dvsk)


    ### VERIFIER ###
    # 1st relation: `A_bar - d == A'*-e + ick_0*r2`
    lhs_1 = add(A_bar, neg(d))
    t_1_prime = add(wsum([A_prime, ick[0]], [s_e, s_r_2]), multiply(lhs_1, c_1))

    # 2nd relation: `g1 + \sum_{i \in D}(ick_{i+1}*a_i) == d*r3 + ick_0*-s' + ick_1*-tsk + \sum_{i \notin D}(ick_{i+1}*-a_i)`
    lhs_2 = add(G1, wsum([ick[D[0]+1], ick[D[1]+1]], [attrs[D[0]-1], attrs[D[1]-1]]))
    t_2_prime = add(wsum([d, ick[0], ick[1], ick[D_bar[0]+1], ick[D_bar[1]+1]], [s_r_3, s_s_prime, s_tsk, s_a_3, s_a_4]), multiply(lhs_2, c_1))

    # 3rd relation: t_u == \sum_i^{W-1}\sum_{j \in I}(ck_i*a_j) + ck_W*o
    lhs_3 = t_u
    t_3_prime = add(wsum(ck, [s_a_4, s_o]), neg(multiply(lhs_3, c_1)))

    # 4th relation: dvpk == g*dvsk
    lhs_4 = dvpk
    t_4_prime = add(wsum([g], [s_r_dvsk]), multiply(lhs_4, c_2))

    c_prime = compute_challenge([n, A_prime, A_bar, d, t_1_prime, t_2_prime, t_3_prime, t_4_prime, G1, D, I, ck, ick, ipk]) % curve_order

    print()
    print((c_1 + c_2) % curve_order, c_prime, t_1, t_1_prime, t_2, t_2_prime, t_3, t_3_prime, t_4, t_4_prime, sep="\n")

def test_raw_prototype_designated_verifier_proof():
    ### HOLDER ###
    L = 4
    attrs = [30, 31, 32, 429]


    ### ISSUER ###
    (ick, ipk, isk) = BBSPlusKeyGen(L)


    ### SECURE ELEMENT ###
    tsk = random()
    tpk = multiply(ick[1], tsk)


    ### ISSUER ###
    sig = BBSPlusSign(isk, ick, tpk, attrs)


    ### VERIFIER ###
    g = make_generators(G1, 1)[0]
    dvsk = random()
    dvpk = multiply(g, dvsk)
    n = random()
    D = [1, 2] # disclosed attribute indices
    I = [4] # undisclosed attribute indices to pass to circuit
    W = len(I)
    ck = make_generators(G1, W+1) # circuit's commitment key (final generator is for opening in Pedersen commitment)


    ### HOLDER ###
    D_bar = [3, 4] # undisclosed attribute indices

    sigOk = BBSPlusVerify(ipk, ick, tpk, attrs, sig)
    assert sigOk

    (A, e, s) = sig

    """ Generate cc-zkSNARK proof over attributes """
    u = [attrs[i-1] for i in I]
    o = random() # opening (blinding)
    t_u = wsum(ck, u + [o]) # Pedersen commitment of the circuit's witnesses

    """ Randomize BBS+ credential """
    r_1, r_2 = random(), random()
    r_3 = pow(r_1, -1, curve_order)

    # b = g1 + ick_0*s + tpk + \sum_{i=1}^{L}(ick_{i+1}*a_i)
    b = wsum([G1, ick[0], tpk] + ick[2:], 
        [1, s, 1] + attrs)
    # A' = A*r_1
    A_prime = multiply(A, r_1)
    # A_bar = A'*-e + b*r_1
    A_bar = add(neg(multiply(A_prime, e)), multiply(b, r_1))
    # d = b*r_1 + ick_0*-r_2
    d = add(multiply(b, r_1), neg(multiply(ick[0], r_2)))
    # s' = s - r_2*r_3
    s_prime = s - r_2 * r_3


    """ verifier now knows valid (A_prime, A_bar, d) """
    r_a_3, r_a_4 = random(), random()
    r_e, r_r_2, r_r_3, r_s_prime, r_tsk, r_o, c_1, r_dvsk = random(), random(), random(), random(), random(), random(), random(), random()

    # Cheat in 1st relation: `A_bar - d == A'*-e + ick_0*r2`
    lhs_1 = add(A_bar, neg(d))
    t_1 = wsum([A_prime, ick[0], lhs_1], [r_e, r_r_2, c_1])

    # Cheat in 2nd relation: `g1 + \sum_{i \in D}(ick_{i+1}*a_i) == d*r3 + ick_0*-s' + ick_1*-tsk + \sum_{i \notin D}(ick_{i+1}*-a_i)`
    lhs_2 = add(G1, wsum([ick[D[0]+1], ick[D[1]+1]], [attrs[D[0]-1], attrs[D[1]-1]]))
    t_2 = wsum([d, ick[0], ick[1], ick[D_bar[0]+1], ick[D_bar[1]+1], lhs_2], [r_r_3, r_s_prime, r_tsk, r_a_3, r_a_4, c_1])

    # Cheat in 3rd relation: t_u == \sum_i^{W-1}\sum_{j \in I}(ck_i*a_j) + ck_W*o
    lhs_3 = t_u
    t_3 = add(wsum(ck, [r_a_4, r_o]), neg(multiply(lhs_3, c_1)))

    # 4th relation: dvpk == g*dvsk
    t_4 = wsum([g], [r_dvsk])

    c = compute_challenge([n, A_prime, A_bar, d, t_1, t_2, t_3, t_4, G1, D, I, ck, ick, ipk]) % curve_order

    c_2 = (c - c_1) % curve_order

    # create responses
    s_tsk     = r_tsk
    s_a_3     = r_a_3
    s_a_4     = r_a_4
    s_e       = r_e
    s_r_2     = r_r_2
    s_r_3     = r_r_3
    s_s_prime = r_s_prime
    s_o       = r_o
    s_r_dvsk  = (r_dvsk - ((c_2 * dvsk) % curve_order)) % curve_order


    ### VERIFIER ###
    # 1st relation: `A_bar - d == A'*-e + ick_0*r2`
    lhs_1 = add(A_bar, neg(d))
    t_1_prime = add(wsum([A_prime, ick[0]], [s_e, s_r_2]), multiply(lhs_1, c_1))

    # 2nd relation: `g1 + \sum_{i \in D}(ick_{i+1}*a_i) == d*r3 + ick_0*-s' + ick_1*-tsk + \sum_{i \notin D}(ick_{i+1}*-a_i)`
    lhs_2 = add(G1, wsum([ick[D[0]+1], ick[D[1]+1]], [attrs[D[0]-1], attrs[D[1]-1]]))
    t_2_prime = add(wsum([d, ick[0], ick[1], ick[D_bar[0]+1], ick[D_bar[1]+1]], [s_r_3, s_s_prime, s_tsk, s_a_3, s_a_4]), multiply(lhs_2, c_1))

    # 3rd relation: t_u == \sum_i^{W-1}\sum_{j \in I}(ck_i*a_j) + ck_W*o
    lhs_3 = t_u
    t_3_prime = add(wsum(ck, [s_a_4, s_o]), neg(multiply(lhs_3, c_1)))

    # 4th relation: dvpk == g*dvsk
    lhs_4 = dvpk
    t_4_prime = add(wsum([g], [s_r_dvsk]), multiply(lhs_4, c_2))

    c_prime = compute_challenge([n, A_prime, A_bar, d, t_1_prime, t_2_prime, t_3_prime, t_4_prime, G1, D, I, ck, ick, ipk]) % curve_order

    print()
    print((c_1 + c_2) % curve_order, c_prime, t_1, t_1_prime, t_2, t_2_prime, t_3, t_3_prime, t_4, t_4_prime, sep="\n")

def test_sigma_pok_discrete_log_disjunction_case_1():
    # PK((x1, x2, x3) or x4): (g1^x1 = y1 and g2^x2.g3^x3 = y2) or g4^x4 = y3
    # CASE 1: prover only knows x4
    g1, g2, g3, g4 = make_generators(G1, 4)
    x1 = random()
    y1 = wsum([g1], [x1])
    x2 = random()
    x3 = random()
    y2 = wsum([g2, g3], [x2, x3])
    x4 = random()
    y3 = wsum([g4], [x4])

    r1 = random()
    r2 = random()
    r3 = random()
    r4 = random()
    w = random()
    cm1 = SchnorrCommitment.new([g1, y1], [r1, w], True) # cheat
    cm2 = SchnorrCommitment.new([g2, g3, y2], [r2, r3, w], True) # cheat
    cm3 = SchnorrCommitment.new([g4], [r4])
    c = compute_challenge([g1, g2, g3, g4, y1, y2, y3, cm1.t, cm2.t, cm3.t]) % curve_order
    c1 = w # cheat
    c2 = (c - w) % curve_order
    resp1 = cm1.response() # cheat
    resp2 = cm2.response() # cheat
    resp3 = cm3.response([x4], c2)
    # prover sends verifier: (c1, c2, resp1, resp2, resp3)

    # verifier
    t1_prime = resp1.t_prime([g1], y1, c1)
    t2_prime = resp2.t_prime([g2, g3], y2, c1)
    t3_prime = resp3.t_prime([g4], y3, c2)

    c_prime = compute_challenge([g1, g2, g3, g4, y1, y2, y3, t1_prime, t2_prime, t3_prime]) % curve_order
    assert c_prime == (c1 + c2) % curve_order

def test_sigma_pok_discrete_log_disjunction_case_2():
    # PK((x1, x2, x3) or x4): (g1^x1 = y1 and g2^x2.g3^x3 = y2) or g4^x4 = y3
    # CASE 2: prover only knows x1, x2, x3
    g1, g2, g3, g4 = make_generators(G1, 4)
    x1 = random()
    y1 = wsum([g1], [x1])
    x2 = random()
    x3 = random()
    y2 = wsum([g2, g3], [x2, x3])
    x4 = random()
    y3 = wsum([g4], [x4])

    r1 = random()
    r2 = random()
    r3 = random()
    r4 = random()
    w = random()
    cm1 = SchnorrCommitment.new([g1], [r1])
    cm2 = SchnorrCommitment.new([g2, g3], [r2, r3])
    cm3 = SchnorrCommitment.new([g4, y3], [r4, w], True) # cheat
    c = compute_challenge([g1, g2, g3, g4, y1, y2, y3, cm1.t, cm2.t, cm3.t]) % curve_order
    c1 = (c - w) % curve_order
    c2 = w # cheat
    resp1 = cm1.response([x1], c1)
    resp2 = cm2.response([x2, x3], c1)
    resp3 = cm3.response() # cheat
    # prover sends verifier: (c1, c2, resp1, resp2, resp3)

    # verifier
    t1_prime = resp1.t_prime([g1], y1, c1)
    t2_prime = resp2.t_prime([g2, g3], y2, c1)
    t3_prime = resp3.t_prime([g4], y3, c2)

    c_prime = compute_challenge([g1, g2, g3, g4, y1, y2, y3, t1_prime, t2_prime, t3_prime]) % curve_order
    assert c_prime == (c1 + c2) % curve_order

def test_helper():
    # PK{(tsk): tpk = h1^tsk}(n)
    h1 = make_generators(G1, 1)[0]
    tsk = random()
    tpk = wsum([h1], [tsk])

    # freshness challenge from issuer
    n = random()

    # prover creates proof
    r1 = random()
    cm = SchnorrCommitment.new([h1], [r1])
    t = cm.t
    c = compute_challenge([h1, tpk, t, n]) % curve_order
    s = cm.response([tsk], c)
    # send proof as (c, s) to issuer along with the public key tpk

    # issuer verifies proof
    t_prime = s.t_prime([h1], tpk, c)
    c_prime = compute_challenge([h1, tpk, t_prime, n]) % curve_order
    print(c, c_prime)
    assert c_prime == c
