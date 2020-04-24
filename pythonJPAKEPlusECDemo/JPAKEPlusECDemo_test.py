from JPAKEPlusECDemo import JPAKEPlusECDemo
from ChaumPedersonZKP import ChaumPedersonZKP
from SchnorrZKP import SchnorrZKP


def preTest():
    jpp = JPAKEPlusECDemo()
    jpp.DEBUG = False
    return jpp

def test_verify_round_one():
    jpp = preTest()
    r = jpp.round_one(3)
    a = jpp.verify_round_one(r, 3)
    assert a == True

def test_keys_are_equivalent():
    jpp = preTest()
    n = 3
    r = jpp.round_one(n)
    jpp.verify_round_one(r, n)
    r2 = jpp.round_two(r, n)
    jpp.verify_round_two(r, r2, n)
    r3 = jpp.round_three(r, r2, n)
    jpp.verify_round_three(r, r2, r3, n)
    keys = jpp.compute_key(r, r3, n)
    assert keys[0] == keys[1] == keys[2]