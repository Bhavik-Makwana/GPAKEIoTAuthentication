from ecpy.curves     import Curve,Point
import random
import time
import numpy as np
import hashlib
import sys
from SchnorrZKP import SchnorrZKP
from ChaumPedersonZKP import ChaumPedersonZKP
import hmac
import traceback

class JPAKEPlusECDemo:

    def __init__(self):
        self.cv = Curve.get_curve('NIST-P256')
        self.sStr = "deadbeef"
        self.s = self.getSHA256_s(self.sStr)
        self.G = self.cv.generator
        self.N = self.cv.order
        self.Q = self.cv.field
        self.h = self.cv.cofactor
        self.times = []
        self.DEBUG = False


    def round_one(self, n):
        aij = [[]]
        bij = [[]]
        gPowBij = [[]]
        gPowAij = [[]]
        yi = []
        gPowYi = []
        gPowZi = []
        schnorrZKPaij = [[]]
        schnorrZKPbij = [[]]
        schnorrZKPyi = [[]]
        signerID = []
        for i in range(n):
            signerID.append(0)
            schnorrZKPyi.append(0)
            yi.append(0)
            gPowYi.append(0)
            gPowZi.append(0)
            for j in range(n):
                aij[i].append(0)
                bij[i].append(0)
                gPowAij[i].append(0)
                gPowBij[i].append(0)
                schnorrZKPaij[i].append(0)
                schnorrZKPbij[i].append(0)
            aij.append([])
            bij.append([])
            gPowAij.append([])
            gPowBij.append([])
            schnorrZKPaij.append([])
            schnorrZKPbij.append([])

        t1 = time.time()
        for i in range(0, n):
            signerID[i] = str(i)
            for j in range(0, n):
                if i == j:
                    continue
                aij[i][j] = random.randint(1, self.N)
                AIJ = self.G.mul(aij[i][j])
                gPowAij[i][j] = AIJ
                schnorrZKP = SchnorrZKP()
                schnorrZKP.generateZKP(self.cv, self.G, self.N, aij[i][j], AIJ, signerID[i])
                schnorrZKPaij[i][j] = schnorrZKP
                
                bij[i][j] = random.randint(1, self.N)
                BIJ = self.G.mul(bij[i][j])
                gPowBij[i][j] = BIJ
                schnorrZKP = SchnorrZKP()
                schnorrZKP.generateZKP(self.cv, self.G, self.N, bij[i][j], BIJ, signerID[i])
                schnorrZKPbij[i][j] = schnorrZKP
            
            yi[i] = random.randint(1, self.N)
            gPowYi[i] = self.G.mul(yi[i])     
            schnorrZKP = SchnorrZKP()   
            schnorrZKP.generateZKP(self.cv, self.G, self.N, yi[i], gPowYi[i], signerID[i])
            schnorrZKPyi[i] = schnorrZKP
            # schnorrZKPyi[i][1] = schnorrZKP.getR()    
        data = {}
        data["aij"] = aij
        data["bij"] = bij
        data["gPowBij"] = gPowBij
        data["gPowAij"] = gPowAij
        data["yi"] = yi
        data["gPowYi"] = gPowYi
        data["gPowZi"] = gPowZi
        data["schnorrZKPaij"] = schnorrZKPaij
        data["schnorrZKPbij"] = schnorrZKPbij
        data["schnorrZKPyi"] = schnorrZKPyi
        data["signerID"] = signerID
        t2 = time.time()
        out = "Round 1: ", (t2-t1)/n
        self.print_debug(out, self.DEBUG)
        self.times.append((t2-t1)/n)
        return data

    def verify_round_one(self, r1, n):
        startTime = time.time()
        for i in range(n):
            if i == n-1:
                iPlusOne = 0
            else:
                iPlusOne = i+1
            if i == 0:
                iMinusOne = n-1
            else:
                iMinusOne = i-1

            current = r1["signerID"][i]
            rightNeighbour = int(r1["signerID"][iPlusOne])
            leftNeighbour = int(r1["signerID"][iMinusOne])
            leftPoint = r1["gPowYi"][leftNeighbour]
            rightPoint = r1["gPowYi"][rightNeighbour]
            r1["gPowZi"][i] = rightPoint.sub(leftPoint)
            temp = self.cv.encode_point(r1["gPowZi"][i])
            temp = int.from_bytes(temp, byteorder='big', signed=False)
            if  temp == 1:
                print("Round 1 verification failed at checking g^{y_{i+1}}/g^{y_{i-1}}!=1 for i=",i)
                return False

        duration = time.time() - startTime

        # Verification
        startTime = time.time()
        for i in range(n):
            # ith participant
            for j in range(n):
                if i==j:
                    continue

                # Check ZKP{bji}
                BIJ = r1["gPowBij"][j][i]
                V = r1["schnorrZKPbij"][j][i].getV()
                r = r1["schnorrZKPbij"][j][i].getR()
                # print(self.verifyZKP(self.G, BIJ, V, r, r1["signerID"][j]))
                if not self.verifyZKP(self.G, BIJ, V, r, r1["signerID"][j]): 
                    print("Round 1 verification failed at checking SchnorrZKP for bij. (i,j)=","(", i, ",", j, ")")
                    return False

                # check g^{b_ji} != 1
                temp = bytearray(self.cv.encode_point(r1["gPowBij"][j][i]))
                temp = int.from_bytes(temp, byteorder='big', signed=False)
                if  temp == 0:
                    print("Round 1 verification failed at checking g^{ji} !=1")
                    return False

                # Check ZKP{aji}
                AIJ = r1["gPowAij"][j][i]
                V = r1["schnorrZKPaij"][j][i].getV()
                if not self.verifyZKP(self.G, AIJ, V, r1["schnorrZKPaij"][j][i].getR(), r1["signerID"][j]): 
                    print("Round 1 verification failed at checking SchnorrZKP for aij. (i,j)=","(", i, ",", j, ")")
                    return False


                # Check ZKP{yi}
                YI = r1["gPowYi"][j]
                V = r1["schnorrZKPyi"][j].getV()
                if not self.verifyZKP(self.G, YI, V, r1["schnorrZKPyi"][j].getR(), r1["signerID"][j]): 
                    print("Round 1 verification failed at checking SchnorrZKP for yi. (i,j)=","(", i, ",", j, ")")
                    return False
        endTime = time.time()
        out = "Round 1v: ", (duration + (endTime-startTime)/n)
        self.print_debug(out, self.DEBUG)
        self.times.append(duration + (endTime-startTime)/n)


    def round_two(self, r1, n):
        self.print_debug("ROUND 2", self.DEBUG)
        startTime = time.time()

        bijs =[[]]
        newGen = [[]]
        newGenPowBijs = [[]]
        schnorrZKPbijs = [[]]
        for i in range(n):
            for j in range(n):
                bijs[i].append(0)
                newGen[i].append(0)
                newGenPowBijs[i].append(0)
                schnorrZKPbijs[i].append(0)
            bijs.append([])
            newGen.append([])
            newGenPowBijs.append([])
            schnorrZKPbijs.append([])

        for i in range(n):
            # Each participant sends newGen^{bij * s} and ZKP{bij * s}
            for j in range(n):
                if i == j:
                    continue
                
                # g^{a_ij} * g^{a_ji} * g^{b_jj} mod p
                newGenAij = r1["gPowAij"][i][j]
                newGenAji = r1["gPowAij"][j][i]
                newGenBji = r1["gPowBij"][j][i]
                newGenEC = newGenAij.add(newGenAji).add(newGenBji)
                newGen[i][j] = newGenEC

                # b_ij * s
                bijs[i][j] = r1["bij"][i][j] * self.s % self.N

                # (g^{a_ij} * g^{a_ji} * g^{b_jj} mod p)^{b_ij * s}
                newGenPowBijs[i][j] = newGenEC.mul(bijs[i][j])

                zkpBijs = SchnorrZKP()
                zkpBijs.generateZKP(self.cv, newGenEC, self.N, bijs[i][j], newGenPowBijs[i][j], r1["signerID"][i])
                schnorrZKPbijs[i][j] =  zkpBijs

        data = {}
        data["bijs"] = bijs
        data["newGen"] = newGen
        data["newGenPowBijs"] = newGenPowBijs
        data["schnorrZKPbijs"] = schnorrZKPbijs
        endTime = time.time()
        out = "Round 2: ", (endTime-startTime)/n
        self.print_debug(out, self.DEBUG)
        self.times.append((endTime-startTime)/n)
        return data

    def verify_round_two(self, r1, r2, n):
        self.print_debug("************ VERIFY ROUND 2 ***********", False)
        startTime = time.time()
        for i in range(n):
            # each participant verifies ZKP{bijs}
            for j in range(n):
                if (i == j):
                    continue
                # Check ZKP{bji}
                newGenEC = r2["newGen"][j][i]
                newGenPowBijsEC = r2["newGenPowBijs"][j][i]
                V = r2["schnorrZKPbijs"][j][i].getV()
                r = r2["schnorrZKPbijs"][j][i].getR()
                if (not self.verifyZKP(newGenEC, newGenPowBijsEC, V, r, r1["signerID"][j])):
                    print("newGenEC Round 2 verification failed at checking SchnorrZKP for bij. (i,j)="+"(", i + ",", j,  ")")
                    return False
        endTime = time.time()
        out = "Round 2v:", (endTime-startTime)
        self.print_debug(out, self.DEBUG)
        self.times.append((endTime-startTime)/n)
        return True


    def round_three(self, r1, r2, n):
        self.print_debug("ROUND 3", False)
        startTime = time.time()

        chaumPedersonZKPi = []
        gPowZiPowYi = []
        hMacsKC = [[]]
        hMacsMAC = [[]]
        pairwiseKeysKC = [[]]
        pairwiseKeysMAC = [[]]
        for i in range(n):
            gPowZiPowYi.append(0)
            chaumPedersonZKPi.append(0)
            for j in range(n):
                hMacsKC[i].append(0)
                hMacsMAC[i].append(0)
                pairwiseKeysKC[i].append(0)
                pairwiseKeysMAC[i].append(0)
            hMacsKC.append([])
            hMacsMAC.append([])
            pairwiseKeysKC.append([])
            pairwiseKeysMAC.append([])
        
        for i in range(n):
            zi = r1["gPowZi"][i]
            yi = r1["yi"][i]
            gPowZiPowYi[i] = zi.mul(yi)
            chaumPedersonZKP = ChaumPedersonZKP(self.cv)


            chaumPedersonZKP.generateZKP(self.G, self.N, r1["gPowYi"][i], r1["yi"][i], self.h, r1["gPowZi"][i],
                    zi.mul(yi),
                    r1["signerID"][i],
                    self.Q)
            chaumPedersonZKPi[i] = chaumPedersonZKP

            # Compute pairwise keys
            for j in range(n):
                if (i == j):
                    continue

                # Kji = (Bji/g^(bij * bji * s))^bij
                gPowBijEC = r1["gPowBij"][j][i]
                bijsEC = r2["bijs"][i][j]

                newGenPowBijsEC = r2["newGenPowBijs"][j][i]
                bijEC = r1["bij"][i][j]
                rawKey = newGenPowBijsEC.sub(gPowBijEC.mul(bijsEC)).mul(bijEC)

                pairwiseKeysMAC[i][j] = self.getSHA256s(rawKey, "MAC")
                pairwiseKeysKC[i][j] = self.getSHA256s(rawKey, "KC")

                # Compute MAC
                hmacName = "HMac-SHA256"

                try:      
                    key = pairwiseKeysMAC[i][j].to_bytes(32, 'big')
                    mac = hmac.new(key)
                    mac.update(bytearray(self.cv.encode_point(r1["gPowYi"][i])))
                    mac.update(bytearray(self.cv.encode_point(r1["schnorrZKPyi"][i].getV())))
                    mac.update(r1["schnorrZKPyi"][i].getR().to_bytes(32, byteorder='big'))
                    mac.update(bytearray(self.cv.encode_point(gPowZiPowYi[i])))
                    mac.update(bytearray(self.cv.encode_point(chaumPedersonZKPi[i].getGPowS())))
                    mac.update(bytearray(self.cv.encode_point(chaumPedersonZKPi[i].getGPowZPowS())))
                    mac.update(chaumPedersonZKPi[i].getT().to_bytes(32, byteorder='big'))
                    b = mac.hexdigest()
                    as_int = int(b, 16)
                    hMacsMAC[i][j] =  as_int
                except Exception as e:
                    print(e)
                    return False

                # Compute HMAC for key confirmation
                try:
                    key = pairwiseKeysKC[i][j].to_bytes(32, 'big')
                    mac = hmac.new(key)
                    mac.update(b"KC")
                    mac.update(i.to_bytes(32, byteorder='big'))
                    mac.update(j.to_bytes(32, byteorder='big'))
                    mac.update(bytearray(self.cv.encode_point(r1["gPowAij"][i][j])))
                    mac.update(bytearray(self.cv.encode_point(r1["gPowBij"][i][j])))
                    mac.update(bytearray(self.cv.encode_point(r1["gPowAij"][j][i])))
                    mac.update(bytearray(self.cv.encode_point(r1["gPowBij"][j][i])))
                    b = mac.hexdigest()
                    as_int = int(b, 16)
                    hMacsKC[i][j] = as_int
                except Exception as e:
                    print(e)
                    return False

            
        data = {}
        data["chaumPedersonZKPi"] = chaumPedersonZKPi
        data["gPowZiPowYi"] = gPowZiPowYi
        data["hMacsKC"] = hMacsKC
        data["hMacsMAC"] = hMacsMAC
        data["pairwiseKeysKC"] = pairwiseKeysKC
        data["pairwiseKeysMAC"] = pairwiseKeysMAC

        endTime = time.time()
        out = "Round 3:", (endTime-startTime)/ n
        self.print_debug(out, self.DEBUG)
        self.times.append((endTime-startTime)/n)
        return data

    def verify_round_three(self, r1, r2, r3, n):
        startTime = time.time()
        
        for i in range(n):
            # ith participant
            for j in range(n):
                # check ZKP - except ith
                if i == j:
                    continue

                if not self.verifyChaumPedersonZKP(self.G,
                        r1["gPowYi"][j],
                        r1["gPowZi"][j],
                        r3["gPowZiPowYi"][j],
                        r3["chaumPedersonZKPi"][j].getGPowS(),
                        r3["chaumPedersonZKPi"][j].getGPowZPowS(),
                        r3["chaumPedersonZKPi"][j].getT(),
                        str(j)):
                    return False

                # Check key confirmation - except ith
                hmacName = "HMac-SHA256"

                if i == j:
                    continue

                key = r3["pairwiseKeysKC"][i][j]

                try:
                    mac = hmac.new(key.to_bytes(32, 'big'))
                    
                    mac.update(b"KC")
                    mac.update(j.to_bytes(32, byteorder='big'))
                    mac.update(i.to_bytes(32, byteorder='big'))                
                    mac.update(bytearray(self.cv.encode_point(r1["gPowAij"][j][i])))
                    mac.update(bytearray(self.cv.encode_point(r1["gPowBij"][j][i])))
                    mac.update(bytearray(self.cv.encode_point(r1["gPowAij"][i][j])))
                    mac.update(bytearray(self.cv.encode_point(r1["gPowBij"][i][j])))
                    b = mac.hexdigest()
                    as_int = int(b, 16)
                    if as_int != r3["hMacsKC"][j][i]:
                        print("Round 3 verification failed at checking KC for (i,j)=(", i, ",", j,")")
                        return False
                except Exception as e:
                    print(e)
                    traceback.print_exc()
                    return False
                

                # Check MACs - except ith
                if i == j:
                    continue

                key = r3["pairwiseKeysMAC"][i][j]
                try:
                    mac = hmac.new(key.to_bytes(32, 'big'))
                    

                    mac.update(bytearray(self.cv.encode_point(r1["gPowYi"][j])))
                    mac.update(bytearray(self.cv.encode_point(r1["schnorrZKPyi"][j].getV())))
                    mac.update(r1["schnorrZKPyi"][j].getR().to_bytes(32, 'big'))
                    mac.update(bytearray(self.cv.encode_point(r3["gPowZiPowYi"][j])))
                    mac.update(bytearray(self.cv.encode_point(r3["chaumPedersonZKPi"][j].getGPowS())))
                    mac.update(bytearray(self.cv.encode_point(r3["chaumPedersonZKPi"][j].getGPowZPowS())))
                    mac.update(r3["chaumPedersonZKPi"][j].getT().to_bytes(32, 'big'))
                    b = mac.hexdigest()
                    as_int = int(b, 16)
                    if as_int != r3["hMacsMAC"][j][i]:
                        print("Round 2 verification failed at checking MACs for (i,j)=(",i,",",j,")")
                        return False
                except Exception as e:
                    print(e)
                    traceback.print_exc()
                    return False

        endTime = time.time()
        out = "Round 3v:", (endTime-startTime)/n
        self.print_debug(out, self.DEBUG)
        self.times.append((endTime-startTime)/n)
        return True

    def compute_key(self, r1, r3, n):
        self.print_debug("*********** KEY COMPUTATION ***********", self.DEBUG)
        startTime = time.time()
        sessionKeys = []
        for i in range(n):
            sessionKeys.append(0);
        for i in range(n):
            # ith participant
            cyclicIndex = self.getCyclicIndex(i-1, n)
            gPowYiEC = r1["gPowYi"][int(r1["signerID"][cyclicIndex])]
            firstTerm = gPowYiEC.mul(r1["yi"][i] * n)
            finalTerm = firstTerm
            for j in range(n-1):
                cyclicIndex = self.getCyclicIndex(i+j, n)
                gPowZiPowYiEC = r3["gPowZiPowYi"][int(r1["signerID"][cyclicIndex])]
                interTerm = gPowZiPowYiEC.mul(n-1-j)
                finalTerm = finalTerm.add(interTerm)
            key = self.getSHA256_ec(finalTerm)
            sessionKeys[i] = key
        endTime = time.time()
        out = "Key:", (endTime-startTime)/n
        self.print_debug(out, self.DEBUG)
        self.times.append((endTime-startTime)/n)
        # for i in sessionKeys:
        #     print(i)
        return key

    def getSHA256_ec(self, s):
        m = hashlib.sha256()
        try:
            sBytes = bytearray(self.cv.encode_point(s))
            m.update(bytearray(len(sBytes))[:4])
            m.update(sBytes)
        except Exception as e:
            print(e)
            traceback.print_exc()
        b = m.hexdigest()
        as_int = int(b, 16)
        return as_int

    def getCyclicIndex(self, i, n):
        if i<0:
            return i+n
        elif i>=n:
            return i-n
        else:
            return i

    def getSHA256s (self, s, strn):
        m = hashlib.sha256()
        try:
            sBytes = bytearray(self.cv.encode_point(s))
            strnBytes = bytearray()
            strnBytes.extend(map(ord, str(strn)))
            
            m.update(bytearray(len(sBytes))[:4])
            m.update(sBytes)
            m.update(bytearray(len(strnBytes))[:4])
            m.update(strnBytes)
        except Exception as e:
            print(e)
        b = m.hexdigest()
        as_int = int(b, 16)
        return as_int

    def getSHA256(self, cv, generator, V, X, userID):
        m = hashlib.sha256()
        try:
            GBytes = bytearray(self.cv.encode_point(generator))
            VBytes = bytearray(self.cv.encode_point(V))
            XBytes = bytearray(self.cv.encode_point(X))
            userIDBytes = bytearray()
            userIDBytes.extend(map(ord, str(userID)))
            # It's good practice to prepend each item with a 4-byte length
            m.update(bytearray(len(GBytes))[:4])
            m.update(GBytes)

            m.update(bytearray(len(VBytes))[:4])
            m.update(VBytes)

            m.update(bytearray(len(XBytes))[:4])
            m.update(XBytes)

            m.update(bytearray(len(userIDBytes))[:4])
            m.update(userIDBytes)
        except Exception as e:
            print(e)
            print("SHA256 failed")
        b = m.hexdigest()
        as_int = int(b, 16)
        return as_int

    def verifyChaumPedersonZKP(self, G, gPowX, gPowZ, gPowZPowX, gPowS, gPowZPowS, t, signerID):

        # ZKP: {A=g^s, B=(g^z)^s, t}
        self.h = self.getSHA256_cp(self.cv, G, gPowX, gPowZ, gPowZPowX, gPowS, gPowZPowS, signerID)
        # check a) - omitted as it's been done in round 1
        # if (gPowX.compareTo(BigInteger.ONE) == -1 ||
        # 		gPowX.compareTo(q.subtract(BigInteger.ONE)) == 1 ||
        # 		gPowX.modPow(q, p).compareTo(BigInteger.ONE) != 0) {
        # 	return false
        # }
        

        # Check b) - only partial redundant checks not repeated. e.g., the order of g^z implied by ZKP checks in round 1
        if gPowZ.x == 1 and gPowZ.y == 1:
            return False

        # Check c) - full check
        if gPowZPowX.x < 0 or gPowZPowX.x > (self.Q-1) or gPowZPowX.y < 0 or gPowZPowX.y > (self.Q-1):
            return False

        # Check d) - Use the straightforward way with 2 exp. Using a simultaneous computation technique only needs 1 exp.
        # g^s = g^t (g^x)^h
        gPowt = G.mul(t).add(gPowX.mul(self.h))
        if not gPowt.eq(gPowS):
            return False

        # Check e) - Use the same method as in d)
        # (g^z)^s = (g^z)^t ((g^x)^z)^h
        if not gPowZ.mul(t).add(gPowZPowX.mul(self.h)).eq(gPowZPowS):
            return False
        return True

    def verifyZKP(self, generator, X, V, r, userID):
        # ZKP: {V=G*v, r} 
        self.h = self.getSHA256(self.cv, generator, V, X, userID)

        # Public key validation based on p. 25
        # http://cs.ucsb.edu/~koc/ccs130h/notes/ecdsa-cert.pdf

        # 1. X != infinity
        # if (X.isInfinity()){
        #     return false
        # }
        
        # 2. Check x and y coordinates are in Fq, i.e., x, y in [0, q-1]
        if not (X.x > 0 or X.x < (self.Q-1) or X.y > 0 or X.y < (self.Q-1)):
            return False
        

        # 3. Check X lies on the curve
        try:
            self.cv.is_on_curve(X)
        except Exception as e:
            print(e)
            return False
        

        # 4. Check that nX = infinity.
        # It is equivalent - but more more efficient - to check the coFactor*X is not infinity
        # if (X.multiply(h).isInfinity()):
        #     return False
        

        # Now check if V = G*r + X*h.
        # Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
        temp = generator.mul(r).add(X.mul(self.h % self.N))
        if (V.eq(temp)) :
            return True
        
        else:
            return False
        

    def getSHA256_cp(self, cv, generator, gPowX, gPowZ, gPowZPowX, gPowS, gPowXPowS, userID):
        m = hashlib.sha256()
        try:
            GBytes = bytearray(self.cv.encode_point(generator))
            gPowXBytes = bytearray(self.cv.encode_point(gPowX))
            gPowZBytes = bytearray(self.cv.encode_point(gPowZ))
            gPowZPowXBytes = bytearray(self.cv.encode_point(gPowZPowX))
            gPowZPowXBytes = bytearray(self.cv.encode_point(gPowZPowX))
            gPowSBytes = bytearray(self.cv.encode_point(gPowS))
            gPowXPowSBytes = bytearray(self.cv.encode_point(gPowXPowS))
            userIDBytes = bytearray()
            userIDBytes.extend(map(ord, str(userID)))

            m.update(bytearray(len(GBytes))[:4])
            m.update(GBytes)
            
            m.update(bytearray(len(gPowXBytes))[:4])
            m.update(gPowXBytes)

            m.update(bytearray(len(gPowZBytes))[:4])
            m.update(gPowZBytes)

            m.update(bytearray(len(gPowZPowXBytes))[:4])
            m.update(gPowZPowXBytes)

            m.update(bytearray(len(gPowSBytes))[:4])
            m.update(gPowSBytes)

            m.update(bytearray(len(gPowXPowSBytes))[:4])
            m.update(gPowXPowSBytes)
            m.update(bytearray(len(userIDBytes))[:4])
            m.update(userIDBytes)

        except Exception as e:
            print(e)

        b = m.hexdigest()
        as_int = int(b, 16)
        return as_int

    def getSHA256_s(self, s):
        m = hashlib.sha256()

        try:
            userIDBytes = bytearray()
            userIDBytes.extend(map(ord, s))

            m.update(bytearray(len(userIDBytes))[:4])
            m.update(userIDBytes)
        except Exception as e:
            print(e)
        
        b = m.hexdigest()
        as_int = int(b, 16)
        return as_int

    def test(self, n):
        r = self.round_one(n)
        self.verify_round_one(r, n)
        r2 = self.round_two(r, n)
        self.verify_round_two(r, r2, n)
        r3 = self.round_three(r, r2, n)
        self.verify_round_three(r, r2, r3, n)
        self.compute_key(r, r3, n)
        for i in self.times:
            print(round(i*100, 3), " ", end=" ")
        self.times = []
    def print_debug(self, str, flag):
        if flag:
            print(str)

jppec = JPAKEPlusECDemo()
print("1       1v      2       2v      3       3v      KC   (ms)")
for i in range(3, 7):
    jppec.test(i)
    print("")
    