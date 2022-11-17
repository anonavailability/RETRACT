# Author: Anon

from hashlib import sha256, sha512
from math import ceil
import time
import secrets
from py_ecc.bn128 import (
    multiply,
    add,
)

def random(random_bits=256, seed=None):
    num_bytes = ceil(random_bits / 8)
    if seed is None:
        randomness = secrets.token_bytes(num_bytes)
    else:
        randomness = sha512(b"%i" % seed).digest()[:num_bytes]
    return int(randomness.hex(), 16)

# Modification of https://github.com/gdanezis/petlib/blob/master/examples/zkp.py
def compute_challenge(elements):
    """Packages a challenge in a bijective way"""
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return int(H.digest().hex(), 16)

# multi scalar multiplication
def wsum(bases, scalars):
    res = multiply(bases[0], scalars[0])
    for b,s in zip(bases[1:], scalars[1:]):
        res = add(res, multiply(b, s))
    return res

def make_generators(group, num_generators):
    generators = [
        multiply(group, random())
        for i in range(num_generators)
    ]
    return generators

def exec_and_measure_elapsed(func, *args):
    start = time.time()
    ret_val = func(*args)
    end = time.time()
    print ("Time elapsed for call to %s():" %func.__name__, end - start)
    return ret_val
