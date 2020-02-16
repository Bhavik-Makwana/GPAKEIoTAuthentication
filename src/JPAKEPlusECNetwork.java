import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;

import JPAKEEllipticCurvePOJOs.*;
import JPAKEEllipticCurvePOJOs.SchnorrZKP;
import com.google.gson.Gson;
//import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class JPAKEPlusECNetwork {
    private ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
    // Domain parameters
    private ECCurve.Fp ecCurve = (ECCurve.Fp)ecSpec.getCurve();
    private BigInteger a = ecCurve.getA().toBigInteger();
    private BigInteger b = ecCurve.getB().toBigInteger();
    private BigInteger q = ecCurve.getQ();
    private BigInteger coFactor = ecSpec.getH(); // Not using the symbol "h" here to avoid confusion as h will be used later in SchnorrZKP.
    private BigInteger nEC = ecSpec.getN();
    private ECPoint G = ecSpec.getG();


    String sStr;
    BigInteger p;
//    BigInteger q;
    BigInteger g;
    int n;
    BigInteger s;

    int clientId;

    // *********************************** ROUND 1 ***********************************
    private HashMap<Long, BigInteger> aij = new HashMap<>();
    private HashMap<Long, byte[]> gPowAij = new HashMap<>();
    private HashMap<Long, SchnorrZKP> schnorrZKPaij = new HashMap<>();
    private HashMap<Long, BigInteger> bij = new HashMap<>();
    private HashMap<Long, byte[]>  gPowBij = new HashMap<>();
    private HashMap<Long, SchnorrZKP> schnorrZKPbij = new HashMap<>();
    private BigInteger yi;
    private byte[] gPowYi;
    private byte[] gPowZi;
    private SchnorrZKP schnorrZKPyi = new SchnorrZKP();
    private String signerID;
    SchnorrZKP schnorrZKP = new SchnorrZKP();

    // *********************************** ROUND 2 ***********************************
//    BigInteger [][] newGen = new BigInteger [n][n];
    HashMap<Long, BigInteger> newGen = new HashMap<>();
    //    BigInteger [][] bijs = new BigInteger [n][n];
    HashMap<Long, BigInteger> bijs = new HashMap<>();
    //    BigInteger [][] newGenPowBijs = new BigInteger [n][n];
    HashMap<Long, BigInteger> newGenPowBijs = new HashMap<>();;
    //    BigInteger [][][] schnorrZKPbijs = new BigInteger [n][n][2];
    HashMap<Long, ArrayList<BigInteger>> schnorrZKPbijs = new HashMap<>();

    // *********************************** ROUND 3 ***********************************
//    BigInteger [] gPowZiPowYi = new BigInteger [n];
    BigInteger gPowZiPowYi;
    //    BigInteger [][] chaumPedersonZKPi = new BigInteger [n][3]; // {g^s, (g^z)^s, t}
    ArrayList<BigInteger> chaumPedersonZKPi = new ArrayList<>();
    //    BigInteger [][] pairwiseKeysMAC = new BigInteger [n][n];
    HashMap<Long, BigInteger> pairwiseKeysMAC = new HashMap<>();
    //    BigInteger [][] pairwiseKeysKC = new BigInteger [n][n];
    HashMap<Long, BigInteger> pairwiseKeysKC = new HashMap<>();
    //    BigInteger [][] hMacsMAC = new BigInteger [n][n];
    HashMap<Long, BigInteger> hMacsMAC = new HashMap<>();
    //    BigInteger [][] hMacsKC = new BigInteger [n][n];
    HashMap<Long, BigInteger> hMacsKC = new HashMap<>();
    //   ************************************ KEYS ************************************
    BigInteger sessionKeys;


    ArrayList<Long> clients;

    public JPAKEPlusECNetwork(String sStr, BigInteger p, BigInteger q, BigInteger g, int n, String id, ArrayList<Long> clients, int clientID) {
        this.sStr = sStr;
        this.p = p;
//        this.q = q;
        this.g = g;
        this.n = n;
        this.signerID = id;
        this.clients = clients;
        this.s = getSHA256(this.sStr);
        this.clientId = clientID;
    }


    public ECRoundOne roundOne() {
        long cID = (long) clientId;
        System.out.println("*************** ROUND 1 ***************");
        int n = clients.size();

        // signerId[i] = i + ""
        signerID = clientId + "";
        HashMap<Long, ECPoint> temp = new HashMap<>();
        // aij in [0, q-1], b_ij in [1, q-1]

        for (int j=0; j<n; j++) {
            System.out.println(clients.get(j) instanceof Long);
            long jID = clients.get(j);
            if (cID==jID){
                continue;
            }

            // aij and ZKP
            aij.put(jID, org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
                    nEC.subtract(BigInteger.ONE), new SecureRandom()));

//            gPowAij.put(jID, g.modPow(aij.get(jID), p));
            ECPoint AIJ = G.multiply(aij.get(jID));
            gPowAij.put(jID, AIJ.getEncoded(false));
            SchnorrZKP zkpAij = new SchnorrZKP();
            zkpAij.generateZKP(G, nEC, aij.get(jID), AIJ, signerID);
            schnorrZKPaij.put(jID, zkpAij);

            // bij and ZKP
            bij.put(jID, org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
                    nEC.subtract(BigInteger.ONE), new SecureRandom()));

            ECPoint BIJ = G.multiply(bij.get(jID));
            gPowBij.put(jID, BIJ.getEncoded(false));
            SchnorrZKP zkpBij = new SchnorrZKP();
            zkpBij.generateZKP(G, nEC, bij.get(jID), BIJ, signerID);
            schnorrZKPbij.put(jID, zkpBij);
        }

        // yi from Zq and ZKP
        yi = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
                nEC.subtract(BigInteger.ONE), new SecureRandom());

        ECPoint YI = G.multiply(yi);
        gPowYi = YI.getEncoded(false);

        signerID = clientId + "";
        schnorrZKP.generateZKP(G, nEC, yi, YI, signerID);
        schnorrZKPyi = schnorrZKP;

        System.out.println("********** SEND ROUND 1 DATA **********");

        ECRoundOne dataObject = new ECRoundOne();
        dataObject.setAij(aij);
        dataObject.setBij(bij);
        dataObject.setgPowAij(gPowAij);
        dataObject.setgPowBij(gPowBij);

        dataObject.setgPowYi(gPowYi);
//        dataObject.setgPowZi(gPowZi.getEncoded(false));
        dataObject.setSchnorrZKPaij(schnorrZKPaij);
        dataObject.setSchnorrZKPbij(schnorrZKPbij);
        dataObject.setSchnorrZKPyi(schnorrZKPyi);
        dataObject.setYi(yi);
        dataObject.setSignerID(signerID);

        return dataObject;
    }

    public boolean verifyRoundOne(ECRoundOneResponse r) {
        // VERIFICATION
        long cID = (long) clientId;
        System.out.println("************ VERIFY ROUND 1 ***********");
        for (int i=0; i<n; i++) {

            int iPlusOne = (i==n-1) ? 0: i+1;
            int iMinusOne = (i==0) ? n-1 : i-1;

            long current = Long.parseLong(r.getSignerID().get(i));
            long rightNeighbour = Long.parseLong(r.getSignerID().get(iPlusOne));
            long leftNeighbour = Long.parseLong(r.getSignerID().get(iMinusOne));

            ECPoint leftPoint = ecCurve.decodePoint(r.getgPowYi().get(leftNeighbour));
            ECPoint rightPoint = ecCurve.decodePoint(r.getgPowYi().get(rightNeighbour));
            r.getgPowZi().put(current, rightPoint.subtract(leftPoint).getEncoded(false));
            if(new BigInteger(r.getgPowZi().get(current)).compareTo(BigInteger.ONE) == 0) {
                System.out.println("Round 1 verification failed at checking g^{y_{i+1}}/g^{y_{i-1}}!=1 for i="+i);
                return false;
            }
        }


        for (int j=0; j<n; j++) {
            long jID = clients.get(j);
            if (cID==jID) {
                continue;
            }

            // Check ZKP{bji}
            ECPoint BIJ = ecCurve.decodePoint(r.getgPowBij().get(jID).get(cID));

            ECPoint V = ecCurve.decodePoint(r.getSchnorrZKPbij().get(jID).get(cID).getV());
            if (!verifyZKP(G,
                    BIJ,
                    V,
                    r.getSchnorrZKPbij().get(jID).get(cID).getr(),
                    Long.toString(clients.get(j)))) {
                System.out.println("Round 1 verification failed at checking SchnorrZKP for bij. (i,j)="+"(" + cID + "," +jID + ")");
                System.exit(0);
            }
            else {
                System.out.println("ALL GOOD");
            }

            // check g^{b_ji} != 1
            if (new BigInteger(r.getgPowBij().get(jID).get(cID)).compareTo(BigInteger.ONE) == 0) {
                System.out.println("Round 1 verification failed at checking g^{ji} !=1");
                return false;
            }

            // Check ZKP{aji}
            ECPoint AIJ = ecCurve.decodePoint(r.getgPowAij().get(jID).get(cID));
            V = ecCurve.decodePoint(r.getSchnorrZKPaij().get(jID).get(cID).getV());
            if (!verifyZKP(G,
                    AIJ,
                    V,
                    r.getSchnorrZKPaij().get(jID).get(cID).getr(),
                    Long.toString(clients.get(j)))) {
                System.out.println("Round 1 verification failed at checking SchnorrZKP for aij. (i,j)="+"(" + cID + "," + jID + ")");
                return false;
            }

            // Check ZKP{yi}
            ECPoint YI = ecCurve.decodePoint(r.getgPowYi().get(jID));
            V = ecCurve.decodePoint(r.getSchnorrZKPyi().get(jID).getV());
            if (!verifyZKP(G,
                    YI,
                    V,
                    r.getSchnorrZKPyi().get(jID).getr(),
                    Long.toString(clients.get(j)))) {
                System.out.println("Round 1 verification failed at checking SchnorrZKP for yi. (i,j)="+"(" + cID + "," +jID + ")");
                return false;
            }
        }
        return true;
    }

    public RoundTwo roundTwo(RoundOneResponse r) {
        System.out.println("*************** ROUND 2 ***************");
        long cID = (long) clientId;
        // Each participant sends newGen^{bij * s} and ZKP{bij * s}
        for (int j=0; j<n; j++) {
            long jID = clients.get(j);
            if (cID==jID){
                continue;
            }
            // g^{a_ij} * g^{a_ji} * g^{b_jj} mod p
            newGen.put(jID,
                    r.getgPowAij().get(cID).get(jID)
                            .multiply(r.getgPowAij().get(jID).get(cID))
                            .multiply(r.getgPowBij().get(jID).get(cID)).mod(p));

            // b_ij * s
            bijs.put(jID, r.getBij().get(cID).get(jID).multiply(s).mod(q));

            // (g^{a_ij} * g^{a_ji} * g^{b_jj} mod p)^{b_ij * s}
            newGenPowBijs.put(jID, newGen.get(jID).modPow(bijs.get(jID), p));
//
//            schnorrZKP.generateZKP(p, q, newGen.get(jID), newGenPowBijs.get(jID), bijs.get(jID), signerID);
//            schnorrZKPbijs.put(jID, new ArrayList<>());
//            schnorrZKPbijs.get(jID).add(schnorrZKP.getGenPowV());
//            schnorrZKPbijs.get(jID).add(schnorrZKP.getR());
        }


        RoundTwo data = new RoundTwo();
        data.setBijs(bijs);
        data.setNewGen(newGen);
        data.setNewGenPowBijs(newGenPowBijs);
        data.setSchnorrZKPbijs(schnorrZKPbijs);
        data.setSignerID(signerID);

        return data;
    }

    public boolean verifyRoundTwo(RoundTwoResponse r) {
        System.out.println("************ VERIFY ROUND 2 ***********");
        long cID = (long) clientId;
        //             each participant verifies ZKP{bijs}
        for (int j=0; j<n; j++) {
            long jID = clients.get(j);
            if (cID==jID){
                continue;
            }

            // Check ZKP{bji}
            if(!verifySchnorrZKP(p, q,
                    r.getNewGen().get(jID).get(cID),
                    r.getNewGenPowBijs().get(jID).get(cID),
                    r.getSchnorrZKPbijs().get(jID).get(cID).get(0),
                    r.getSchnorrZKPbijs().get(jID).get(cID).get(1),
                    Long.toString(jID))) {
                System.out.println("Round 2 verification failed at checking SchnorrZKP for bij. (i,j)="+"(" + clientId + "," + jID + ")");
                return false;
            }
        }
        return true;
    }

    public RoundThree roundThree(RoundOneResponse r1, RoundTwoResponse r2) {
        System.out.println("*************** ROUND 3 ***************");
        long cID = (long) clientId;
        gPowZiPowYi = r1.getgPowZi().get(cID).modPow(r1.getYi().get(cID), p);

        ChaumPedersonZKP chaumPedersonZKP = new ChaumPedersonZKP();

        chaumPedersonZKP.generateZKP(p, q, g,
                r1.getgPowYi().get(cID),
                r1.getYi().get(cID),
                r1.getgPowZi().get(cID),
                gPowZiPowYi,
                signerID);

        chaumPedersonZKPi.add(chaumPedersonZKP.getGPowS());
        chaumPedersonZKPi.add(chaumPedersonZKP.getGPowZPowS());
        chaumPedersonZKPi.add(chaumPedersonZKP.getT());

        // Compute pairwise keys
        for (int j=0; j<n; j++) {
            long jID = clients.get(j);
            if (cID==jID){
                continue;
            }

            BigInteger rawKey = r1.getgPowBij().get(jID).get(cID)
                    .modPow(r2.getBijs().get(cID).get(jID), p)
                    .modInverse(p)
                    .multiply(r2.getNewGenPowBijs().get(jID).get(cID))
                    .modPow(r1.getBij().get(cID).get(jID), p);

            pairwiseKeysMAC.put(jID, getSHA256(rawKey, "MAC"));
            pairwiseKeysKC.put(jID, getSHA256(rawKey, "KC"));

            // Compute MAC
            String hmacName = "HMac-SHA256";

            try {
                SecretKey key = new SecretKeySpec(pairwiseKeysMAC.get(jID).toByteArray(), hmacName);
                Mac mac = Mac.getInstance(hmacName, "BC");
                mac.init(key);
                mac.update(r1.getgPowYi().get(cID).toByteArray());
                mac.update(r1.getSchnorrZKPyi().get(cID).get(0).toByteArray());
                mac.update(r1.getSchnorrZKPyi().get(cID).get(1).toByteArray());
                mac.update(gPowZiPowYi.toByteArray());
                mac.update(chaumPedersonZKPi.get(0).toByteArray());
                mac.update(chaumPedersonZKPi.get(1).toByteArray());
                mac.update(chaumPedersonZKPi.get(2).toByteArray());

                hMacsMAC.put(jID, new BigInteger(mac.doFinal()));

            } catch(Exception e) {

                e.printStackTrace();
                System.exit(0);

            }

            // Compute HMAC for key confirmation
            try{
                SecretKey key = new SecretKeySpec(pairwiseKeysKC.get(jID).toByteArray(), hmacName);
                Mac mac = Mac.getInstance(hmacName, "BC");
                mac.init(key);
                mac.update("KC".getBytes());
                mac.update(new BigInteger(""+cID).toByteArray());
                mac.update(new BigInteger(""+jID).toByteArray());

                mac.update(r1.getgPowAij().get(cID).get(jID).toByteArray());
                mac.update(r1.getgPowBij().get(cID).get(jID).toByteArray());

                mac.update(r1.getgPowAij().get(jID).get(cID).toByteArray());
                mac.update(r1.getgPowBij().get(jID).get(cID).toByteArray());

                hMacsKC.put(jID, new BigInteger(mac.doFinal()));
            } catch(Exception e) {

                e.printStackTrace();
                System.exit(0);

            }
        }

        RoundThree data = new RoundThree();
        data.setChaumPedersonZKPi(chaumPedersonZKPi);
        data.setgPowZiPowYi(gPowZiPowYi);
        data.sethMacsKC(hMacsKC);
        data.sethMacsMAC(hMacsMAC);
        data.setPairwiseKeysKC(pairwiseKeysKC);
        data.setPairwiseKeysMAC(pairwiseKeysMAC);

        return data;
    }

    public boolean roundFour(RoundOneResponse r1, RoundTwoResponse r2, RoundThreeResponse r3) {
        System.out.println("*************** ROUND 4 ***************");
        long cID = (long) clientId;
        // ith participant
        for (int j=0; j<n; j++) {
            // check ZKP - except ith
            long jID = clients.get(j);
            if (cID==jID) {
                continue;
            }

            if (!verifyChaumPedersonZKP(p, q, g,
                    r1.getgPowYi().get(jID),
                    r1.getgPowZi().get(jID),
                    r3.getgPowZiPowYi().get(jID),
                    r3.getChaumPedersonZKPi().get(jID).get(0),
                    r3.getChaumPedersonZKPi().get(jID).get(1),
                    r3.getChaumPedersonZKPi().get(jID).get(2),
                    Long.toString(jID))) {
                System.out.println("Round 2 verification failed at checking jth Chaum-Pederson for (i,j)=("+cID+","+jID+")");
                return false;
            }

            // Check key confirmation - except ith
            String hmacName = "HMac-SHA256";

            if (cID == jID) {
                continue;
            }

            SecretKey key = new SecretKeySpec(r3.getPairwiseKeysKC().get(cID).get(jID).toByteArray(), hmacName);

            try {
                Mac mac = Mac.getInstance(hmacName, "BC");
                mac.init(key);

                mac.update("KC".getBytes());
                mac.update(new BigInteger(""+jID).toByteArray());
                mac.update(new BigInteger(""+cID).toByteArray());

                mac.update(r1.getgPowAij().get(jID).get(cID).toByteArray());
                mac.update(r1.getgPowBij().get(jID).get(cID).toByteArray());

                mac.update(r1.getgPowAij().get(cID).get(jID).toByteArray());
                mac.update(r1.getgPowBij().get(cID).get(jID).toByteArray());
                BigInteger temp = new BigInteger(mac.doFinal());
                System.out.println(temp);
                System.out.println(r3.gethMacsKC().get(jID).get(cID));
                if (temp.compareTo(r3.gethMacsKC().get(jID).get(cID)) != 0) {
                    System.out.println("Round 3 verification failed at checking KC for (i,j)=("+cID+","+jID+")");
                    return false;
                }
            } catch(Exception e) {
                e.printStackTrace();
                System.exit(0);
            }

            // Check MACs - except ith
            if (cID == jID) {
                continue;
            }

            key = new SecretKeySpec(r3.getPairwiseKeysMAC().get(cID).get(jID).toByteArray(), hmacName);

            try {
                Mac mac = Mac.getInstance(hmacName, "BC");
                mac.init(key);
                mac.reset();

                mac.update(r1.getgPowYi().get(jID).toByteArray());
                mac.update(r1.getSchnorrZKPyi().get(jID).get(0).toByteArray());
                mac.update(r1.getSchnorrZKPyi().get(jID).get(1).toByteArray());

                mac.update(r3.getgPowZiPowYi().get(jID).toByteArray());
                mac.update(r3.getChaumPedersonZKPi().get(jID).get(0).toByteArray());
                mac.update(r3.getChaumPedersonZKPi().get(jID).get(1).toByteArray());
                mac.update(r3.getChaumPedersonZKPi().get(jID).get(2).toByteArray());

                if (new BigInteger(mac.doFinal()).compareTo(r3.gethMacsMAC().get(jID).get(cID)) != 0) {
                    System.out.println("Round 2 verification failed at checking MACs for (i,j)=("+cID+","+jID+")");
                    return false;
                }
            }catch(Exception e){

                e.printStackTrace();
                System.exit(0);

            }
        }
        return true;
    }

    public BigInteger computeKey(RoundOneResponse r1, RoundThreeResponse r3) {
        HashMap<Long, BigInteger> multipleSessionKeys = new HashMap<>();
        System.out.println("*********** KEY COMPUTATION ***********");
        for (int i=0; i<n; i++) {
            long iID = clients.get(i);
            // ith participant

            int cyclicIndex = getCyclicIndex(i-1, n);
            BigInteger firstTerm = r1.getgPowYi().get(clients.get(cyclicIndex))
                    .modPow(r1.getYi().get(iID).multiply(BigInteger.valueOf(n)), p);
            BigInteger finalTerm = firstTerm;

            for (int j=0; j<(n-1) ; j++) {
                cyclicIndex = getCyclicIndex(i+j, n);
                BigInteger interTerm = r3.getgPowZiPowYi().get(clients.get(cyclicIndex))
                        .modPow(BigInteger.valueOf(n-1-j), p);
                finalTerm = finalTerm.multiply(interTerm).mod(p);
            }

            multipleSessionKeys.put(clients.get(i), getSHA256(finalTerm));
            sessionKeys =  getSHA256(finalTerm);

        }

        for (int i=0; i<n; i++) {

            System.out.println("Session key " + i + " for client " + clients.get(i) + ": " + multipleSessionKeys.get(clients.get(i)).toString(16));



        }
        return multipleSessionKeys.get((long) clientId);
    }
    public int getCyclicIndex (int i, int n){

        if (i<0){
            return i+n;
        }else if (i>=n){
            return i-n;
        }else {
            return i;
        }
    }

    public BigInteger getSHA256(ECPoint generator, ECPoint V, ECPoint X, String userID) {

        MessageDigest sha256 = null;

        try {
            sha256 = MessageDigest.getInstance("SHA-256");

            byte [] GBytes = generator.getEncoded(false);
            byte [] VBytes = V.getEncoded(false);
            byte [] XBytes = X.getEncoded(false);
            byte [] userIDBytes = userID.getBytes();

            // It's good practice to prepend each item with a 4-byte length
            sha256.update(ByteBuffer.allocate(4).putInt(GBytes.length).array());
            sha256.update(GBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(VBytes.length).array());
            sha256.update(VBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(XBytes.length).array());
            sha256.update(XBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(userIDBytes.length).array());
            sha256.update(userIDBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return new BigInteger(sha256.digest());
    }

    public BigInteger getSHA256(BigInteger g, BigInteger gPowX, BigInteger gPowZ, BigInteger gPowZPowX,
                                BigInteger gPowS, BigInteger gPowXPowS, String userID) {

        MessageDigest sha256 = null;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");

            byte [] gBytes = g.toByteArray();
            byte [] gPowXBytes = gPowX.toByteArray();
            byte [] gPowZBytes = gPowZ.toByteArray();
            byte [] gPowZPowXBytes = gPowZPowX.toByteArray();
            byte [] gPowSBytes = gPowS.toByteArray();
            byte [] gPowXPowSBytes = gPowXPowS.toByteArray();
            byte [] userIDBytes = userID.getBytes();

            sha256.update(ByteBuffer.allocate(4).putInt(gBytes.length).array());
            sha256.update(gBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowXBytes.length).array());
            sha256.update(gPowXBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowZBytes.length).array());
            sha256.update(gPowZBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowZPowXBytes.length).array());
            sha256.update(gPowZPowXBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowSBytes.length).array());
            sha256.update(gPowSBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(gPowXPowSBytes.length).array());
            sha256.update(gPowXPowSBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(userIDBytes.length).array());
            sha256.update(userIDBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return new BigInteger(sha256.digest());

    }


    public static BigInteger getSHA256(BigInteger gen, BigInteger genPowV, BigInteger genPowX, String userID) {

        MessageDigest sha256 = null;

        try {
            sha256 = MessageDigest.getInstance("SHA-256");

            byte [] genBytes = gen.toByteArray();
            byte [] genPowVBytes = genPowV.toByteArray();
            byte [] genPowXBytes = genPowX.toByteArray();
            byte [] userIDBytes = userID.getBytes();

            // Prepend each item with a 4-byte length
            sha256.update(ByteBuffer.allocate(4).putInt(genBytes.length).array());
            sha256.update(genBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(genPowVBytes.length).array());
            sha256.update(genPowVBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(genPowXBytes.length).array());
            sha256.update(genPowXBytes);

            sha256.update(ByteBuffer.allocate(4).putInt(userIDBytes.length).array());
            sha256.update(userIDBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return new BigInteger(sha256.digest());
    }

    public BigInteger getSHA256 (String s)
    {
        MessageDigest sha256 = null;

        try {
            sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(s.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new BigInteger(sha256.digest());
    }

    public BigInteger getSHA256 (BigInteger s)
    {
        MessageDigest sha256 = null;

        try {
            sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(s.toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new BigInteger(sha256.digest());
    }

    public BigInteger getSHA256 (BigInteger s, String str)
    {
        MessageDigest sha256 = null;

        try {
            sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(s.toByteArray());
            sha256.update(str.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new BigInteger(sha256.digest());
    }

    /*
     * Check
     * a) g^x in [1, q-1]
     * b) (g^x)^q = 1
     * c) g^v = g^r (g^x)^h
     *
     * Note: the case of x = 0 is not excluded in this routine. Handle that in the upstream if you need to.
     */
    public boolean verifySchnorrZKP(BigInteger p, BigInteger q, BigInteger gen, BigInteger genPowX, BigInteger genPowV, BigInteger r, String userID) {

        // ZKP: {V=gen^v, r}
        BigInteger h = getSHA256(gen, genPowV, genPowX, userID);
//        System.out.println(genPowX.compareTo(BigInteger.ZERO) == 1 );
//        System.out.println(genPowX.compareTo(p) == -1);
//        System.out.println(genPowX.modPow(q, p).compareTo(BigInteger.ONE) == 0);
//        System.out.println(gen.modPow(r,p).multiply(genPowX.modPow(h,p)).mod(p).compareTo(genPowV) == 0);
//        System.out.println(genPowX.compareTo(BigInteger.ZERO) == 1 &&
//                genPowX.compareTo(p) == -1 &&
//                genPowX.modPow(q, p).compareTo(BigInteger.ONE) == 0 &&
//                gen.modPow(r,p).multiply(genPowX.modPow(h,p)).mod(p).compareTo(genPowV) == 0);
        if (genPowX.compareTo(BigInteger.ZERO) == 1 && // gen^x > 0
                genPowX.compareTo(p) == -1 && // gen^x < p
                genPowX.modPow(q, p).compareTo(BigInteger.ONE) == 0 && // gen^x^q = 1

                /* A straightforward way to compute g^r * g^x^h needs 2 exp. Using
                 * a simultaneous computation technique would only need 1 exp.
                 */
                gen.modPow(r,p).multiply(genPowX.modPow(h,p)).mod(p).compareTo(genPowV) == 0) { // gen^v=gen^r * gen^x^h
            return true;
        }
        else {
            return false;
        }
    }

    /*
     * Full checks:
     * a) g^x in [1, q-1] and (g^x)^q = 1
     * b) g^z in [2, q-1] and (g^z)^q = 1
     * c) (g^z)^x in [1, q-1] and (g^z)^x = 1
     * d) g^s = g^t (g^x)^h
     * e) (g^z)^s = (g^z)^t ((g^z)^x)^h
     *
     * Notes:
     *
     * 1) The case of x = 0 is not excluded in this routine. Handle that in the upstream if you need to.
     * 2) Only partial checks are implemented in this routine, since some overlap with the previous
     *    checks in verifying the SchnorrZKP.
     *
     */
    public boolean verifyChaumPedersonZKP(BigInteger p, BigInteger q, BigInteger g, BigInteger gPowX, BigInteger gPowZ,
                                          BigInteger gPowZPowX, BigInteger gPowS, BigInteger gPowZPowS, BigInteger t, String signerID) {

        // ZKP: {A=g^s, B=(g^z)^s, t}
        BigInteger h = getSHA256(g,gPowX,gPowZ,gPowZPowX,gPowS,gPowZPowS,signerID);

        // check a) - omitted as it's been done in round 1
    	/*
       	if (gPowX.compareTo(BigInteger.ONE) == -1 ||
       			gPowX.compareTo(q.subtract(BigInteger.ONE)) == 1 ||
       			gPowX.modPow(q, p).compareTo(BigInteger.ONE) != 0) {
       		return false;
       	}
       	*/

        // Check b) - only partial; redundant checks not repeated. e.g., the order of g^z implied by ZKP checks in round 1
        if (gPowZ.compareTo(BigInteger.ONE) == 0){
            return false;
        }

        // Check c) - full check
        if (gPowZPowX.compareTo(BigInteger.ONE) == -1 ||
                gPowZPowX.compareTo(p.subtract(BigInteger.ONE)) == 1 ||
                gPowZPowX.modPow(q, p).compareTo(BigInteger.ONE) != 0) {

            return false;
        }

        // Check d) - Use the straightforward way with 2 exp. Using a simultaneous computation technique only needs 1 exp.
        // g^s = g^t (g^x)^h
        if (g.modPow(t, p).multiply(gPowX.modPow(h, p)).mod(p).compareTo(gPowS) != 0) {
            return false;
        }

        // Check e) - Use the same method as in d)
        // (g^z)^s = (g^z)^t ((g^x)^z)^h
        if (gPowZ.modPow(t, p).multiply(gPowZPowX.modPow(h, p)).mod(p).compareTo(gPowZPowS) != 0) {
            return false;
        }

        return true;
    }

    public boolean verifyZKP(ECPoint generator, ECPoint X, ECPoint V, BigInteger r, String userID) {

        /* ZKP: {V=G*v, r} */
        BigInteger h = getSHA256(generator, V, X, userID);

        // Public key validation based on p. 25
        // http://cs.ucsb.edu/~koc/ccs130h/notes/ecdsa-cert.pdf

        // 1. X != infinity
        if (X.isInfinity()){
            return false;
        }
        // 2. Check x and y coordinates are in Fq, i.e., x, y in [0, q-1]
        if (X.normalize().getXCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
                X.normalize().getXCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1 ||
                X.normalize().getYCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
                X.normalize().getYCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1) {
            return false;
        }

        // 3. Check X lies on the curve
        try {
            ecCurve.decodePoint(X.getEncoded(false));
        }
        catch(Exception e){
            e.printStackTrace();
            return false;
        }

        // 4. Check that nX = infinity.
        // It is equivalent - but more more efficient - to check the coFactor*X is not infinity
        if (X.multiply(coFactor).isInfinity()) {
            return false;
        }

        // Now check if V = G*r + X*h.
        // Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
        ECPoint temp = generator.multiply(r).add(X.multiply(h.mod(nEC)));
        if (V.equals(temp)) {
            return true;
        }
        else {
            return false;
        }
    }


    public void exitWithError(String s){
        System.out.println("Exit with ERROR: " + s);
        System.exit(0);
    }

    private class ChaumPedersonZKP {

        private BigInteger gPowS = null;
        private BigInteger gPowZPowS = null;
        private BigInteger t = null;

        private ChaumPedersonZKP () {
            // Constructor
        }

        private void generateZKP(BigInteger p, BigInteger q, BigInteger g, BigInteger gPowX, BigInteger x,
                                 BigInteger gPowZ, BigInteger gPowZPowX, String signerID) {

            // Generate s from [1, q-1] and compute (A, B) = (gen^s, genPowZ^s)
            BigInteger s = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
                    q.subtract(BigInteger.ONE), new SecureRandom());
            gPowS = g.modPow(s, p);
            gPowZPowS = gPowZ.modPow(s, p);

            BigInteger h = getSHA256(g,gPowX,gPowZ,gPowZPowX,gPowS,gPowZPowS,signerID); // challenge

            t = s.subtract(x.multiply(h)).mod(q); // t = s-cr
        }

        private BigInteger getGPowS() {
            return gPowS;
        }

        private BigInteger getGPowZPowS() {
            return gPowZPowS;
        }

        private BigInteger getT() {
            return t;
        }
    }



}
