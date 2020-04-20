from ecpy.curves     import Curve,Point
import random
import time
import numpy as np
import hashlib

cv = Curve.get_curve('NIST-P256')
# cv = Curve.get_curve('secp256k1')
# P  = Point(0x65d5b8bf9ab1801c9f168d4815994ad35f1dcb6ae6c7a1a303966b677b813b00,
#            0xe6b865e529b8ecbf71cf966e900477d49ced5846d7662dd2dd11ccd55c0aff7f,
#            cv)
# k  = 0xfb26a4e75eec75544c0f44e937dcf5ee6355c7176600b9688c667e5c283b43c5
# Q  = k*P
# R  = P+Q
G = cv.generator
N = cv.order
Q = cv.field
h = cv.cofactor

# print(type(Q))
# x = int.from_bytes(cv.encode_point(Q), byteorder='big', signed=False)
# x = random.randint(0, Q)
# t1 = time.time()
# print(G.mul(x))
# t2 = time.time()
# print(t2-t1)
# X = random.randint(0, Q)
# print(X)
# print(G.mul(X))



def round_one(n):
    aij = np.zeros([n, n])
    bij = np.zeros([n, n])
    gPowBij = np.zeros([n, n])
    gPowAij = np.zeros([n, n])
    yi = np.zeros(n)
    gPowYi = np.zeros(n)
    gPowZi = np.zeros(n)
    schnorrZKPaij = np.zeros([n, n, 2])
    schnorrZKPbij = np.zeros([n, n, 2])
    schnorrZKPyi = np.zeros([n, 2])
    signerID = np.zeros(n)
    print(signerID)
    schnorrZKP = SchnorrZKP()
    print(N)
    t1 = time.time()
    for i in range(0, n):
        signerID[i] = str(i)
        # for j in range(0, n):
        #     if i == j:
        #         continue
        #     aij[i][j] = random.randint(1, N)
        #     print(aij[i][j])
        #     AIJ = G.mul(aij[i][j])
        #     gPowAij[i][j] = AIJ
            
        #     schnorrZKP.generateZKP(G, N, aij[i][j], AIJ, signerID[i]);
        #     schnorrZKPaij[i][j][0] = schnorrZKP.getGenPowV
        #     schnorrZKPaij[i][j][1] = schnorrZKP.getR
            
        #     bij[i][j] = random.randint(1, N)
        #     BIJ = G.mul(bij[i][j])
        #     gPowBij[i][j] = BIJ
            
        #     schnorrZKP.generateZKP(G, N, bij[i][j], BIJ, signerID[i]);
        #     schnorrZKPbij[i][j][0] = schnorrZKP.getGenPowV
        #     schnorrZKPbij[i][j][1] = schnorrZKP.getR    
        schnorrZKP.test()
        yi = random.randint(1, n)
        gPowYi = G.mul(yi)
        
        schnorrZKP.generateZKP(G, N, yi, gPowYi, signerID[i]);
        schnorrZKyi[i][0] = schnorrZKP.getGenPowV
        schnorrZKPyi[i][1] = schnorrZKP.getR    
        data = 0
    t2 = time.time()
    print("Time: ", t2-t1)
    return data
# round_one()
# print(Curve.get_curve_names())
def getSHA256(cv, generator, V, X, userID):
    m = hashlib.sha256()
    try:
        GBytes = bytearray(cv.encode_point(generator));
        VBytes = bytearray(cv.encode_point(V))
        XBytes = bytearray(cv.encode_point(X));
        userIDBytes = bytearray()
        userIDBytes.extend(map(ord, userID))
        # It's good practice to prepend each item with a 4-byte length
        m.update(bytearray(len(GBytes))[:4]);
        m.update(GBytes);

        m.update(bytearray(len(VBytes))[:4]);
        m.update(VBytes);

        m.update(bytearray(len(XBytes))[:4]);
        m.update(XBytes);

        m.update(bytearray(len(userIDBytes))[:4]);
        m.update(userIDBytes);

    except:
        print("SHA256 failed")
    return m.digest()

class SchnorrZKP:
    V = 0
    r = 0

    def __init__(self): 
        pass
    
    def test(self):
        print("hello")
    def generateZKP(self, generator, n, x, X, userID):
        # Generate a random v from [1, n-1], and compute V = G*v 
        v = random.randint(1, N)
        V = generator.mul(v);

        h = getSHA256(cv, generator, V, X, userID); # h

        r = (v - (x * h)) % n; # r = v-x*h mod n

    def getGenPowV(self):
        return V;

    def getR(self):
        return r

round_one(3)