
/*
 * @author: Anonymized
 */

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.Security;
import java.io.*;

import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SPEKEPlusDemo {

	/*
	 * Safe prime p = 2q + 1 from SRP: http://www.ietf.org/rfc/rfc5054.txt
	 * 2 is the generator for Z_p*. Here we use 3, which is a generator for the subgroup of Z_p* of prime order q.
	 */

	BigInteger p = new BigInteger("AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 16);
	BigInteger q = p.subtract(BigInteger.ONE).divide(new BigInteger("2", 16));
	BigInteger g = new BigInteger("3", 16);
	BigInteger bigTwo = new BigInteger("2", 16);

	long startTime = 0;
	long endTime = 0;
	long duration = 0;

	/*
	 * Common password
	 */
	String sStr = "deadbeef";

	// assume n participants
	int n;

	boolean DEBUG = false;

	// For testing performance
	int maxNumberOfIterations = 31; // at least 2
	int latency [][] = new int [maxNumberOfIterations][5];
	int avgLatency [] = new int [latency[0].length];

    public static void main(String args[]) {

    	SPEKEPlusDemo test = new SPEKEPlusDemo();

    	int maxNoOfParticipants = 20;

    	for (int noOfParticiapnts = 3; noOfParticiapnts < maxNoOfParticipants+1; noOfParticiapnts++){

    		test.startTest(noOfParticiapnts);
    	}
    }

    public SPEKEPlusDemo() {

		// x in [0, q-1]
		BigInteger x = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
    			q.subtract(BigInteger.ONE), new SecureRandom());

    	long startTime = System.currentTimeMillis();

    	for (int i = 0; i<50; i++){

    		g.modPow(x, p);

    	}
    	long endTime = System.currentTimeMillis();

    	System.out.println("The cost of g^x (ms): " + (endTime-startTime)/50);

    }

    private void startTest(int noOfParticiapnts) {

    	this.n = noOfParticiapnts;

    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    	System.out.println("Participants No = " + noOfParticiapnts + "\t Iterations No = " + maxNumberOfIterations);
    	printString("Public parameters for the cyclic group:");
    	printString("p ("+p.bitLength()+" bits): " + p.toString(16));
    	printString("q ("+q.bitLength()+" bits): " + q.toString(16));
    	printString("g ("+g.bitLength()+" bits): " + g.toString(16));
    	printString("p mod q = " + p.mod(q).toString(16));
    	printString("g^{q} mod p = " + g.modPow(q,p).toString(16));
    	printString("");

    	printString("(Secret password used by all participants: "+
    			"\""+sStr+"\")\n");

    	printString("Number of participants: " + n + "\n");

    	for (int i=0; i<maxNumberOfIterations; i++) {

    		run(i);

    	}

    	// print latency measurements
    	printString("");
    	for (int i=0; i<latency.length; i++){

    		for (int j=0; j<latency[0].length; j++){

    			System.out.print(latency[i][j] + "\t");

    			if (i != 0){
    				avgLatency[j] += latency[i][j]; // ignore the first run data
    			}
    		}

    		if (i==0) {
    			System.out.print("(ommited)"); // First run contains some noise; ignored.
    		}
    		System.out.println("");

    	}

    	// print the average values and write a file

    	try {
    		RandomAccessFile file = new RandomAccessFile("SPEKE.txt", "rw");
    		file.skipBytes((int)file.length());

    		System.out.println("---------------------------------------------------------------------");

    		for (int j=0; j<avgLatency.length; j++) {

    			System.out.print(avgLatency[j]/(latency.length-1) + "\t");
    			file.writeBytes(avgLatency[j]/(latency.length-1) + "\t");

    			// Reset the avgLatency
    			avgLatency[j] = 0;
    		}

    		System.out.println();
    		file.writeBytes("\n");


    	}catch(Exception e){

    		e.printStackTrace();
    		System.exit(0);
    	}
    }

    private void run (int numberOfIteration) {


    	// g_s = H(s)^2
    	BigInteger gs = getSHA256(sStr);

    	BigInteger [] xi = new BigInteger [n];
    	BigInteger [] yi = new BigInteger [n];
    	BigInteger [] gsPowXi = new BigInteger [n];
    	BigInteger [] gPowYi = new BigInteger [n];
    	BigInteger [] gPowZi = new BigInteger [n];
    	BigInteger [][] schnorrZKPi = new BigInteger [n][2]; // {g^v, r}
    	String [] signerID = new String [n];

    	// Round 1: P_i sends g_s^{x_i}, g^{y_i}, zkp{y_i}

    	startTime = System.currentTimeMillis();

    	for (int i=0; i<n; i++) {

    		// x_i in [1, q-1]
    		xi[i] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
        			q.subtract(BigInteger.ONE), new SecureRandom());

    		// y_i in [0, q-1]
    		yi[i] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
        			q.subtract(BigInteger.ONE), new SecureRandom());

    		gsPowXi[i] = gs.modPow(xi[i], p);

    		gPowYi[i] = g.modPow(yi[i], p);

    		signerID[i] = i + "";

    		SchnorrZKP schnorrZKP = new SchnorrZKP();
    		schnorrZKP.generateZKP(p, q, g, gPowYi[i], yi[i], signerID[i]);
    		schnorrZKPi[i][0] = schnorrZKP.getGenPowV();
    		schnorrZKPi[i][1] = schnorrZKP.getR();
    	}

    	endTime = System.currentTimeMillis();
    	printString("1). Latency of computing in round 1 per participant (ms):" + (endTime-startTime)/n);
    	latency[numberOfIteration][0] = (int) ((endTime-startTime)/n);

    	// Compute g^{z)i} and verify it isn't 1
    	startTime = System.currentTimeMillis();

    	for (int i=0; i<n; i++) {

    		int iPlusOne = (i==n-1) ? 0: i+1;
			int iMinusOne = (i==0) ? n-1 : i-1;

			gPowZi[i] = gPowYi[iMinusOne].modInverse(p).multiply(gPowYi[iPlusOne]).mod(p);

			if(gPowZi[i].compareTo(BigInteger.ONE) == 0) {
				exitWithError("Round 1 verification failed at checking g^{y_{i+1}}/g^{y_{i-1}}!=1 for i="+i);
			}
    	}

    	duration = System.currentTimeMillis() - startTime;

    	// Verification
    	startTime = System.currentTimeMillis();

    	for (int i=0; i<n; i++) {

    		// ith participant

    		for (int j=0; j<n; j++) {

    			// check gs^{x_i} - except ith
    			if (i==j){
    				continue;
    			}
    			if (gsPowXi[j].compareTo(bigTwo) == -1 ||
    					gsPowXi[j].compareTo(p.subtract(bigTwo)) == 1){
    				exitWithError("Round 1 verification failed at checking gs^{x_j} for j="+j);
    			}

    			// ZKP - except ith
    			if (i==j) {
    				continue;
    			}
    			if (!verifySchnorrZKP(p, q, g, gPowYi[j], schnorrZKPi[j][0], schnorrZKPi[j][1], signerID[j])) {
    				exitWithError("Round 1 verification failed at checking jth SchnorrZKP for j="+j);
    			}
    		}
    	}

    	endTime = System.currentTimeMillis();

    	printString("2). Latency of verifying round 1 data per participant (ms): " + (duration + (endTime-startTime)/n));
    	printString("");
    	latency[numberOfIteration][1] = (int) (duration + (endTime-startTime)/n);

    	BigInteger [] gPowZiPowYi = new BigInteger [n];
    	BigInteger [][] chaumPedersonZKPi = new BigInteger [n][3]; // {g^s, (g^z)^s, t}
    	BigInteger [][] pairwiseKeysMAC = new BigInteger [n][n];
    	BigInteger [][] pairwiseKeysKC = new BigInteger [n][n];
    	BigInteger [][] hMacsMAC = new BigInteger [n][n];
    	BigInteger [][] hMacsKC = new BigInteger [n][n];

    	// Round 2: P_i sends A = {g^{y_i}, ZKP, (g^{z_i})^{y_i}, ZKP}, HMAC authentication tag,
    	// HMAC key confirmation tag
    	startTime = System.currentTimeMillis();

    	for (int i=0; i<n; i++){

    		gPowZiPowYi[i] = gPowZi[i].modPow(yi[i], p);

    		ChaumPedersonZKP chaumPedersonZKP = new ChaumPedersonZKP();

    		chaumPedersonZKP.generateZKP(p, q, g, gPowYi[i], yi[i], gPowZi[i], gPowZiPowYi[i], signerID[i]);

    		chaumPedersonZKPi[i][0] = chaumPedersonZKP.getGPowS();
    		chaumPedersonZKPi[i][1] = chaumPedersonZKP.getGPowZPowS();
    		chaumPedersonZKPi[i][2] = chaumPedersonZKP.getT();

    		// Compute pairwise keys
    		for (int j=0; j<n; j++){

    			if (i==j){
    				continue;
    			}

    			BigInteger rawKey = gsPowXi[j].modPow(xi[i], p);

    			pairwiseKeysMAC[i][j] = getSHA256(rawKey, "MAC");
    			pairwiseKeysKC[i][j] = getSHA256(rawKey, "KC");

    			String hmacName = "HMac-SHA256";

    			try {
    				// Compute HMAC for message authentication
    				SecretKey key = new SecretKeySpec(pairwiseKeysMAC[i][j].toByteArray(), hmacName);
    				Mac mac = Mac.getInstance(hmacName, "BC");
    				mac.init(key);
    				mac.reset();
    				mac.update(gPowYi[i].toByteArray());
    				mac.update(schnorrZKPi[i][0].toByteArray());
    				mac.update(schnorrZKPi[i][1].toByteArray());
    				mac.update(gPowZiPowYi[i].toByteArray());
    				mac.update(chaumPedersonZKPi[i][0].toByteArray());
    				mac.update(chaumPedersonZKPi[i][1].toByteArray());
    				mac.update(chaumPedersonZKPi[i][2].toByteArray());

    				hMacsMAC[i][j] = new BigInteger(mac.doFinal());

    				// Compute HMAC for key confirmation
    				key = new SecretKeySpec(pairwiseKeysKC[i][j].toByteArray(), hmacName);

    				mac.reset();
    				mac.init(key);
    				mac.update("KC".getBytes());
    				mac.update(new BigInteger(""+i).toByteArray());
    				mac.update(new BigInteger(""+j).toByteArray());
    				mac.update(gsPowXi[i].toByteArray());
    				mac.update(gsPowXi[j].toByteArray());

    				hMacsKC[i][j] = new BigInteger(mac.doFinal());

    			}catch(Exception e){

    				e.printStackTrace();
    				System.exit(0);

    			}
    		}
    	}

    	endTime = System.currentTimeMillis();

    	printString("3) Latency of computation in round 2 per participant (ms): " + (endTime-startTime)/n);
    	latency[numberOfIteration][2] = (int) ((endTime-startTime)/n);

    	// Verifying data in Round 2
    	startTime = System.currentTimeMillis();

    	for (int i=0; i<n; i++) {

    		// ith participant
    		for (int j=0; j<n; j++) {

    			// check ZKP - except ith
    			if (i==j) {
    				continue;
    			}
    			if (!verifyChaumPedersonZKP(p, q, g, gPowYi[j], gPowZi[j], gPowZiPowYi[j],
    					chaumPedersonZKPi[j][0], chaumPedersonZKPi[j][1], chaumPedersonZKPi[j][2], signerID[j])) {
    				exitWithError("Round 2 verification failed at checking jth Chaum-Pederson for (i,j)=("+i+","+j+")");
    			}

    			// Check key confirmation - except ith
    			String hmacName = "HMac-SHA256";

    			if (i==j) {
    				continue;
    			}

    			SecretKey key = new SecretKeySpec(pairwiseKeysKC[i][j].toByteArray(), hmacName);

    			try {
    				Mac mac = Mac.getInstance(hmacName, "BC");
    				mac.init(key);

    				mac.update("KC".getBytes());
    				mac.update(new BigInteger(""+j).toByteArray());
    				mac.update(new BigInteger(""+i).toByteArray());
    				mac.update(gsPowXi[j].toByteArray());
    				mac.update(gsPowXi[i].toByteArray());

    				if (new BigInteger(mac.doFinal()).compareTo(hMacsKC[j][i]) != 0) {
    					exitWithError("Round 2 verification failed at checking KC for (i,j)=("+i+","+j+")");

    				}
    			}catch(Exception e){

    				e.printStackTrace();
    				System.exit(0);

    			}

    			// Check MACs - except ith
    			if (i==j) {
    				continue;
    			}

    			key = new SecretKeySpec(pairwiseKeysMAC[i][j].toByteArray(), hmacName);

    			try {
    				Mac mac = Mac.getInstance(hmacName, "BC");
    				mac.init(key);
    				mac.reset();
    				mac.update(gPowYi[j].toByteArray());
    				mac.update(schnorrZKPi[j][0].toByteArray());
    				mac.update(schnorrZKPi[j][1].toByteArray());
    				mac.update(gPowZiPowYi[j].toByteArray());
    				mac.update(chaumPedersonZKPi[j][0].toByteArray());
    				mac.update(chaumPedersonZKPi[j][1].toByteArray());
    				mac.update(chaumPedersonZKPi[j][2].toByteArray());

    				if (new BigInteger(mac.doFinal()).compareTo(hMacsMAC[j][i]) != 0) {
    					exitWithError("Round 2 verification failed at checking MACs for (i,j)=("+i+","+j+")");

    				}
    			}catch(Exception e){

    				e.printStackTrace();
    				System.exit(0);

    			}
    		}
    	}

    	endTime = System.currentTimeMillis();
    	printString("4) Latency of verifying data in round 2 per participant (ms): " + (endTime-startTime)/n);
    	printString("");
    	latency[numberOfIteration][3] = (int) ((endTime-startTime)/n);

    	// Finally, compute the keys
    	startTime = System.currentTimeMillis();
    	BigInteger [] sessionKeys = new BigInteger [n];

    	for (int i=0; i<n; i++) {

    		// ith participant
    		BigInteger firstTerm = gPowYi[getCyclicIndex(i-1,n)].modPow( yi[i].multiply(BigInteger.valueOf(n)), p);
    		BigInteger finalTerm = firstTerm;

    		for (int j=0; j<(n-1) ; j++){

    			BigInteger interTerm = gPowZiPowYi[getCyclicIndex(i+j, n)].modPow(BigInteger.valueOf(n-1-j), p);

    			finalTerm = finalTerm.multiply(interTerm).mod(p);
    		}

    		sessionKeys[i] = getSHA256(finalTerm);
    	}

    	endTime = System.currentTimeMillis();
    	printString("5) Latency of key computation 2 per participant (ms): " + (endTime-startTime)/n);
    	printString("");
    	latency[numberOfIteration][4] = (int) ((endTime-startTime)/n);

    	for (int i=0; i<n; i++) {

    		printString("Session key " + i + ": " + sessionKeys[i].toString(16));

    	}
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

    public BigInteger getSHA256(BigInteger gen, BigInteger genPowV, BigInteger genPowX, String userID) {

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

    public void exitWithError(String s){
    	System.out.println("Exit with ERROR: " + s);
    	System.exit(0);
    }

    public void printString(String s){

    	if (DEBUG){
    		System.out.println(s);
    	}
    }

    public void printStringNoCR(String s){

    	if (DEBUG) {
    		System.out.print(s);
    	}

    }

    // Based on P. 5 at https://eprint.iacr.org/2014/364.pdf
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

    private class SchnorrZKP {

    	private BigInteger genPowV = null;
    	private BigInteger r = null;

    	private SchnorrZKP () {
    		// constructor
    	}

        private void generateZKP (BigInteger p, BigInteger q, BigInteger gen,
			     BigInteger genPowX, BigInteger x, String signerID){

        	/* Generate a random v from [0, q-1], and compute V = gen^v */
        	BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
        			q.subtract(BigInteger.ONE), new SecureRandom());
        	genPowV = gen.modPow(v,p);
        	BigInteger h = getSHA256(gen,genPowV,genPowX,signerID); // h

        	r = v.subtract(x.multiply(h)).mod(q); // r = v-x*h
        }

    	private BigInteger getGenPowV() {
    		return genPowV;
    	}

    	private BigInteger getR() {
    		return r;
    	}
    }
}