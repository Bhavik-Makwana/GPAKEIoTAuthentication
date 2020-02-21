package DemoCode;
/*
 * @author: Anonymized
 */

import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JPAKEPlusDemo {

	/*
	 * (p, q, g) from http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/DSA2_All.pdf
	 */

	// 2048-bit
	BigInteger p = new BigInteger("C196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16);
	BigInteger q = new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16);
	BigInteger g = new BigInteger("A59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16);

	// 3072-bit
	//BigInteger p = new BigInteger("90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD61037E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE05E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA129F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E542D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA632C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0EE6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE030D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504FB0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C560EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73", 16);
	//BigInteger q = new BigInteger("CFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D", 16);
    //BigInteger g = new BigInteger("5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B82846F9A0C393914C792E6A923E2117AB805276A975AADB5261D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B67299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D58E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B988567A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A22D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B", 16);

    BigInteger bigTwo = new BigInteger("2", 16);

	long startTime = 0;
	long endTime = 0;
	long duration = 0;

	/*
	 * Common password
	 */
	String sStr = "deadbeef";
	BigInteger s = getSHA256(sStr);

	// assume n participants
	int n;

	boolean DEBUG = true;

	// For testing performance
	int maxNumberOfIterations = 2; // at least 2
	int latency [][] = new int [maxNumberOfIterations][7];
	int avgLatency [] = new int [7];

    public static void main(String args[]) {

    	JPAKEPlusDemo test = new JPAKEPlusDemo();

    	int maxNoOfParticipants = 3;

    	for (int noOfParticiapnts = 3; noOfParticiapnts <= maxNoOfParticipants+1; noOfParticiapnts++){

    		test.startTest(noOfParticiapnts);
    	}

    }

    public JPAKEPlusDemo() {

		// x in [0, q-1]
		BigInteger x = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
    			q.subtract(BigInteger.ONE), new SecureRandom());

    	long startTime = System.currentTimeMillis();

    	for (int i = 0; i<100; i++){

    		g.modPow(x, p);

    	}
    	long endTime = System.currentTimeMillis();

    	System.out.println("The cost of g^x (ms): " + (endTime-startTime)/100);

    }

	/**
	 * startTest
	 * Run a single test of the JPAKEPlus Protocol
	 * @param noOfParticipants
	 */
	private void startTest(int noOfParticipants) {

    	this.n = noOfParticipants;

    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    	System.out.println("Participants No = " + noOfParticipants + "\t Iterations No = " + maxNumberOfIterations);
    	printString("Public parameters for the cyclic group:"); // printString only displays if debug = true
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
		// col 1: latency of computing round 1 per participant
		// col 2: latency of verifying round 1 per participant
		// col 3: latency of computing round 2 data per participant
		// col 4: latency of verifying round 2 data per participant
		// col 5: latency of computation in round 2 per participant
		// col 6: latency of verifying data in round 2 per participant
		// col 7: latency of key computation 2 per participant
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
    		RandomAccessFile file = new RandomAccessFile("JPAKE.txt", "rw");
    		file.skipBytes((int)file.length());

    		System.out.println("---------------------------------------------------------------------");

    		for (int j=0; j<avgLatency.length; j++) {

    			System.out.print(avgLatency[j]/(latency.length-1) + "\t");
    			file.writeBytes(avgLatency[j]/(latency.length-1) + "\t");

    			// Reset the avgLatency
    			avgLatency[j] = 0;
    		}

    		System.out.println("");
    		file.writeBytes("\n");


    	}catch(Exception e){

    		e.printStackTrace();
    		System.exit(0);
    	}
    }

	/**
	 * run
	 * main function to start JPAKE protocol
	 * @param numberOfIteration
	 */
	private void run (int numberOfIteration) {

    	BigInteger [][] aij = new BigInteger [n][n];
    	BigInteger [][] gPowAij = new BigInteger [n][n];
    	BigInteger [][][] schnorrZKPaij = new BigInteger [n][n][2];

    	BigInteger [][] bij = new BigInteger [n][n];
    	BigInteger [][] gPowBij = new BigInteger [n][n];
    	BigInteger [][][] schnorrZKPbij = new BigInteger [n][n][2];

    	BigInteger [] yi = new BigInteger [n];
    	BigInteger [] gPowYi = new BigInteger [n];
    	BigInteger [] gPowZi = new BigInteger [n];
    	BigInteger [][] schnorrZKPyi = new BigInteger [n][2]; // {g^v, r}

    	String [] signerID = new String [n];

    	SchnorrZKP schnorrZKP = new SchnorrZKP();

    	// Round 1: P_i sends g^{a_{ij}}, g^{b_{ij}} for j in {1...n}\{i}, g^{y_i}, zkp{y_i}

    	startTime = System.currentTimeMillis();

    	for (int i=0; i<n; i++) {

    		signerID[i] = i + "";

    		// aij in [0, q-1], b_ij in [1, q-1]
    		for (int j=0; j<n; j++) {

    			if (i==j){
    				continue;
    			}

    			// aij and ZKP
    			aij[i][j] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
            			q.subtract(BigInteger.ONE), new SecureRandom());

    			gPowAij[i][j] = g.modPow(aij[i][j], p);

    			schnorrZKP.generateZKP(p, q, g, gPowAij[i][j], aij[i][j], signerID[i]);
    			schnorrZKPaij[i][j][0] = schnorrZKP.getGenPowV();
    			schnorrZKPaij[i][j][1] = schnorrZKP.getR();

    			// bij and ZKP
    			bij[i][j] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
            			q.subtract(BigInteger.ONE), new SecureRandom());

    			gPowBij[i][j] = g.modPow(bij[i][j], p);

    			schnorrZKP.generateZKP(p, q, g, gPowBij[i][j], bij[i][j], signerID[i]);
    			schnorrZKPbij[i][j][0] = schnorrZKP.getGenPowV();
    			schnorrZKPbij[i][j][1] = schnorrZKP.getR();
    		}

			// yi from Zq and ZKP
    		yi[i] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
        			q.subtract(BigInteger.ONE), new SecureRandom());

    		gPowYi[i] = g.modPow(yi[i], p);

    		signerID[i] = i + "";

    		schnorrZKP.generateZKP(p, q, g, gPowYi[i], yi[i], signerID[i]);
    		schnorrZKPyi[i][0] = schnorrZKP.getGenPowV();
    		schnorrZKPyi[i][1] = schnorrZKP.getR();
    	}

    	endTime = System.currentTimeMillis();
    	printString("1) Latency of computing in round 1 per participant (ms):" + (endTime-startTime)/n);
    	latency[numberOfIteration][0] = (int) ((endTime-startTime)/n);

    	// Compute g^{z_i} and verify it isn't 1
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

    			if (i==j){
    				continue;
    			}

    			// Check ZKP{bji}
    			if(!verifySchnorrZKP(p, q, g, gPowBij[j][i], schnorrZKPbij[j][i][0], schnorrZKPbij[j][i][1], signerID[j])) {
    				exitWithError("Round 1 verification failed at checking SchnorrZKP for bij. (i,j)="+"(" + i + "," +j + ")");
    			}

    			// check g^{b_ji} != 1
    			if (gPowBij[j][i].compareTo(BigInteger.ONE) == 0){
    				exitWithError("Round 1 verification failed at checking g^{ji} !=1");
    			}

    			// Check ZKP{aji}
    			if(!verifySchnorrZKP(p, q, g, gPowAij[j][i], schnorrZKPaij[j][i][0], schnorrZKPaij[j][i][1], signerID[j])) {
    				exitWithError("Round 1 verification failed at checking SchnorrZKP for aij. (i,j)="+"(" + i + "," +j + ")");
    			}

    			// Check ZKP{yi}
    			if (!verifySchnorrZKP(p, q, g, gPowYi[j], schnorrZKPyi[j][0], schnorrZKPyi[j][1], signerID[j])) {
    				exitWithError("Round 1 verification failed at checking SchnorrZKP for yi. (i,j)="+"(" + i + "," +j + ")");
    			}
    		}
    	}

    	endTime = System.currentTimeMillis();

    	printString("2) Latency of verifying round 1 data per participant (ms): " + (duration + (endTime-startTime)/n));
    	printString("");
    	latency[numberOfIteration][1] = (int) (duration + (endTime-startTime)/n);

    	// Round 2: P_i sends betaij and ZKP{bijs}
    	BigInteger [][] newGen = new BigInteger [n][n];
    	BigInteger [][] bijs = new BigInteger [n][n];
    	BigInteger [][] newGenPowBijs = new BigInteger [n][n];
    	BigInteger [][][] schnorrZKPbijs = new BigInteger [n][n][2];

    	startTime = System.currentTimeMillis();

    	for (int i=0; i<n; i++) {

    		// Each participant sends newGen^{bij * s} and ZKP{bij * s}
    		for (int j=0; j<n; j++) {

    			if (i==j){
    				continue;
    			}

				// g^{a_ij} * g^{a_ji} * g^{b_jj} mod p
    			newGen[i][j] = gPowAij[i][j].multiply(gPowAij[j][i]).multiply(gPowBij[j][i]).mod(p);

    			// b_ij * s
    			bijs[i][j] = bij[i][j].multiply(s).mod(q);

    			// (g^{a_ij} * g^{a_ji} * g^{b_jj} mod p)^{b_ij * s}
    			newGenPowBijs[i][j] = newGen[i][j].modPow(bijs[i][j], p);

    			schnorrZKP.generateZKP(p, q, newGen[i][j], newGenPowBijs[i][j], bijs[i][j], signerID[i]);
    			schnorrZKPbijs[i][j][0] = schnorrZKP.getGenPowV();
    			schnorrZKPbijs[i][j][1] = schnorrZKP.getR();
    		}
    	}

    	endTime = System.currentTimeMillis();
    	printString("3) Latency of computing in round 2 per participant (ms):" + (endTime-startTime)/n);
    	latency[numberOfIteration][2] = (int) ((endTime-startTime)/n);

    	// Verification
    	startTime = System.currentTimeMillis();

    	for (int i=0; i<n; i++) {

    		// each participant verifies ZKP{bijs}

    		for (int j=0; j<n; j++) {

    			if (i==j){
    				continue;
    			}

      			// Check ZKP{bji}
    			if(!verifySchnorrZKP(p, q, newGen[j][i], newGenPowBijs[j][i], schnorrZKPbijs[j][i][0], schnorrZKPbijs[j][i][1], signerID[j])) {
    				exitWithError("Round 2 verification failed at checking SchnorrZKP for bij. (i,j)="+"(" + i + "," +j + ")");
    			}
    		}
    	}

    	endTime = System.currentTimeMillis();

    	printString("4) Latency of verifying round 2 data per participant (ms): " + ((endTime-startTime)/n));
    	printString("");
    	latency[numberOfIteration][3] = (int) ((endTime-startTime)/n);

    	// Round 3: P_i sends A = {g^{y_i}, ZKP, (g^{z_i})^{y_i}, ZKP}, and HMAC(k_{ij}, A)
    	BigInteger [] gPowZiPowYi = new BigInteger [n];
    	BigInteger [][] chaumPedersonZKPi = new BigInteger [n][3]; // {g^s, (g^z)^s, t}
    	BigInteger [][] pairwiseKeysMAC = new BigInteger [n][n];
    	BigInteger [][] pairwiseKeysKC = new BigInteger [n][n];
    	BigInteger [][] hMacsMAC = new BigInteger [n][n];
    	BigInteger [][] hMacsKC = new BigInteger [n][n];

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

    			BigInteger rawKey = gPowBij[j][i].modPow(bijs[i][j], p).modInverse(p).multiply(newGenPowBijs[j][i]).modPow(bij[i][j], p);
    			pairwiseKeysMAC[i][j] = getSHA256( rawKey, "MAC");
    			pairwiseKeysKC[i][j] = getSHA256( rawKey, "KC");

    			// Compute MAC
    			String hmacName = "HMac-SHA256";

    			try {
    				SecretKey key = new SecretKeySpec(pairwiseKeysMAC[i][j].toByteArray(), hmacName);
    				Mac mac = Mac.getInstance(hmacName, "BC");
    				mac.init(key);
    				mac.update(gPowYi[i].toByteArray());
    				mac.update(schnorrZKPyi[i][0].toByteArray());
    				mac.update(schnorrZKPyi[i][1].toByteArray());
    				mac.update(gPowZiPowYi[i].toByteArray());
    				mac.update(chaumPedersonZKPi[i][0].toByteArray());
    				mac.update(chaumPedersonZKPi[i][1].toByteArray());
    				mac.update(chaumPedersonZKPi[i][2].toByteArray());

    				hMacsMAC[i][j] = new BigInteger(mac.doFinal());

    			}catch(Exception e){

    				e.printStackTrace();
    				System.exit(0);

    			}

    				// Compute HMAC for key confirmation
    			try{
    				SecretKey key = new SecretKeySpec(pairwiseKeysKC[i][j].toByteArray(), hmacName);
    				Mac mac = Mac.getInstance(hmacName, "BC");
       				mac.init(key);
    				mac.update("KC".getBytes());
    				mac.update(new BigInteger(""+i).toByteArray());
    				mac.update(new BigInteger(""+j).toByteArray());

    				mac.update(gPowAij[i][j].toByteArray());
    				mac.update(gPowBij[i][j].toByteArray());

    				mac.update(gPowAij[j][i].toByteArray());
    				mac.update(gPowBij[j][i].toByteArray());

    				hMacsKC[i][j] = new BigInteger(mac.doFinal());
    			}catch(Exception e){

    				e.printStackTrace();
    				System.exit(0);

    			}
    		}
    	}

    	endTime = System.currentTimeMillis();

    	printString("5) Latency of computation in round 2 per participant (ms): " + (endTime-startTime)/n);
    	latency[numberOfIteration][4] = (int) ((endTime-startTime)/n);

    	// Verifying data in Round 4
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

    				mac.update(gPowAij[j][i].toByteArray());
    				mac.update(gPowBij[j][i].toByteArray());

    				mac.update(gPowAij[i][j].toByteArray());
    				mac.update(gPowBij[i][j].toByteArray());
 					BigInteger temp = new BigInteger(mac.doFinal());
    				System.out.println(temp);
 					System.out.println(hMacsKC[j][i]);
    				if (temp.compareTo(hMacsKC[j][i]) != 0) {
    					exitWithError("Round 3 verification failed at checking KC for (i,j)=("+i+","+j+")");
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
    				mac.update(schnorrZKPyi[j][0].toByteArray());
    				mac.update(schnorrZKPyi[j][1].toByteArray());

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
    	printString("6) Latency of verifying data in round 2 per participant (ms): " + (endTime-startTime)/n);
    	printString("");
    	latency[numberOfIteration][5] = (int) ((endTime-startTime)/n);

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
    	printString("7) Latency of key computation 2 per participant (ms): " + (endTime-startTime)/n);
    	printString("");
    	latency[numberOfIteration][6] = (int) ((endTime-startTime)/n);

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

        	/* Generate a random v from [1, q-1], and compute V = gen^v */
        	BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
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