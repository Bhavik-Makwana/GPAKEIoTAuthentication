
import random
import hashlib
class ChaumPedersonZKP:
    '''
        This class provides the functionality to generate a 
        ChaumPederson zero-knowledge proof using ecc.
    '''
    gPowS = 0
    gPowZPowS = 0
    t = 0
    cv = 0
    def __init__(self, cv):
        self.cv = cv

    def generateZKP(self, G, N, gPowX, x, h, gPowZ, gPowZPowX, signerID, q):
        '''
            function: generateZKP
            This function creates the parameters needed for a CPZKP.
            params: @G Point
                    @N Point
                    @gPowX Point
                    @x int
                    @h int
                    @gPowZ Point
                    @gPowZPowX Point
                    @signerID string
                    @q int
            @return Null
        '''

        # Generate s from [1, q-1] and compute (A, B) = (gen^s, genPowZ^s)
        s = random.randint(1, q-1)
        # gPowS = g.modPow(s, p)
        self.gPowS = G.mul(s)
        # gPowZPowS = gPowZ.modPow(s, p)
        self.gPowZPowS = gPowZ.mul(s)
        # BigInteger h = getSHA256(G,gPowX,gPowZ,gPowZPowX,gPowS,gPowZPowS,signerID) // challenge
        h = self.getSHA256(self.cv, G, gPowX, gPowZ, gPowZPowX, self.gPowS, self.gPowZPowS, signerID)
        # t = s.subtract(x.multiply(h)).mod(q) // t = s-cr
        self.t = (s - (x * h)) % N
    

    def getGPowS(self):
        return self.gPowS

    def getGPowZPowS(self):
        return self.gPowZPowS

    def getT(self):
        return self.t


    def getSHA256(self, cv, generator, V, X, userID):
        m = hashlib.sha256()
        try:
            GBytes = bytearray(cv.encode_point(generator))
            VBytes = bytearray(cv.encode_point(V))
            XBytes = bytearray(cv.encode_point(X))
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

    def getSHA256(self, cv, generator, gPowX, gPowZ, gPowZPowX, gPowS, gPowXPowS, userID):
        m = hashlib.sha256()
        try:
            GBytes = bytearray(cv.encode_point(generator))
            gPowXBytes = bytearray(cv.encode_point(gPowX))
            gPowZBytes = bytearray(cv.encode_point(gPowZ))
            gPowZPowXBytes = bytearray(cv.encode_point(gPowZPowX))
            gPowZPowXBytes = bytearray(cv.encode_point(gPowZPowX))
            gPowSBytes = bytearray(cv.encode_point(gPowS))
            gPowXPowSBytes = bytearray(cv.encode_point(gPowXPowS))
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
