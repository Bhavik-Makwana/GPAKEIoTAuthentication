import random 
import hashlib
class SchnorrZKP:
    V = 0
    r = 0

    def __init__(self): 
        pass
    
    def test(self):
        print("hello")
    def generateZKP(self, cv, generator, N, x, X, userID):
        # Generate a random v from [1, n-1], and compute V = G*v 
        v = random.randint(1, N)
        self.V = generator.mul(v);

        h = self.getSHA256(cv, generator, self.V, X, userID) # h
        
        self.r = (v - (x * h)) % N # r = v-x*h mod n

    def getV(self):
        return self.V;

    def getR(self):
        return self.r

    def getSHA256(self, cv, generator, V, X, userID):
        m = hashlib.sha256()
        try:
            GBytes = bytearray(cv.encode_point(generator));
            VBytes = bytearray(cv.encode_point(V))
            XBytes = bytearray(cv.encode_point(X));
            userIDBytes = bytearray()
            userIDBytes.extend(map(ord, str(userID)))
            # It's good practice to prepend each item with a 4-byte length
            m.update(bytearray(len(GBytes))[:4]);
            m.update(GBytes);

            m.update(bytearray(len(VBytes))[:4]);
            m.update(VBytes);

            m.update(bytearray(len(XBytes))[:4]);
            m.update(XBytes);

            m.update(bytearray(len(userIDBytes))[:4]);
            m.update(userIDBytes);
        except Exception as e:
            print(e)
            print("SHA256 failed")
        b = m.hexdigest()
        as_int = int(b, 16)
        return as_int
