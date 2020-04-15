package JPAKEPlusEllipticCurve.POJOs;

import JPAKEPlusEllipticCurve.ZKPs.ChaumPedersonZKP;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;

public class ECRoundThree {
    byte[] gPowZiPowYi;
    //    BigInteger [][] chaumPedersonZKPi = new BigInteger [n][3]; // {g^s, (g^z)^s, t}
    ChaumPedersonZKP chaumPedersonZKPi = new ChaumPedersonZKP();
    //    BigInteger [][] pairwiseKeysMAC = new BigInteger [n][n];
    ConcurrentHashMap<Long, BigInteger> pairwiseKeysMAC = new ConcurrentHashMap<>();
    //    BigInteger [][] pairwiseKeysKC = new BigInteger [n][n];
    ConcurrentHashMap<Long, BigInteger> pairwiseKeysKC = new ConcurrentHashMap<>();
    //    BigInteger [][] hMacsMAC = new BigInteger [n][n];
    ConcurrentHashMap<Long, BigInteger> hMacsMAC = new ConcurrentHashMap<>();
    //    BigInteger [][] hMacsKC = new BigInteger [n][n];
    ConcurrentHashMap<Long, BigInteger> hMacsKC = new ConcurrentHashMap<>();

    public byte[] getgPowZiPowYi() {
        return gPowZiPowYi;
    }

    public void setgPowZiPowYi(byte[] gPowZiPowYi) {
        this.gPowZiPowYi = gPowZiPowYi;
    }

    public ChaumPedersonZKP getChaumPedersonZKPi() {
        return chaumPedersonZKPi;
    }

    public void setChaumPedersonZKPi(ChaumPedersonZKP chaumPedersonZKPi) {
        this.chaumPedersonZKPi = chaumPedersonZKPi;
    }

    public ConcurrentHashMap<Long, BigInteger> getPairwiseKeysMAC() {
        return pairwiseKeysMAC;
    }

    public void setPairwiseKeysMAC(ConcurrentHashMap<Long, BigInteger> pairwiseKeysMAC) {
        this.pairwiseKeysMAC = pairwiseKeysMAC;
    }

    public ConcurrentHashMap<Long, BigInteger> getPairwiseKeysKC() {
        return pairwiseKeysKC;
    }

    public void setPairwiseKeysKC(ConcurrentHashMap<Long, BigInteger> pairwiseKeysKC) {
        this.pairwiseKeysKC = pairwiseKeysKC;
    }

    public ConcurrentHashMap<Long, BigInteger> gethMacsMAC() {
        return hMacsMAC;
    }

    public void sethMacsMAC(ConcurrentHashMap<Long, BigInteger> hMacsMAC) {
        this.hMacsMAC = hMacsMAC;
    }

    public ConcurrentHashMap<Long, BigInteger> gethMacsKC() {
        return hMacsKC;
    }

    public void sethMacsKC(ConcurrentHashMap<Long, BigInteger> hMacsKC) {
        this.hMacsKC = hMacsKC;
    }
}
