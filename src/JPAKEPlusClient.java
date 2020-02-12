
import com.google.gson.Gson;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class JPAKEPlusClient {

    BufferedReader in;
    PrintWriter out;
    Gson gson = new Gson();
    ObjectInputStream objectInputStream;
    JFrame frame = new JFrame("Client");
    JTextField textField = new JTextField(40);
    JTextArea messageArea = new JTextArea(8, 40);
    String clientName;
    String data;
    String response;
    String sStr = "deadbeef";
    BigInteger s = getSHA256(sStr);


    int clientId;

    // *********************************** ROUND 1 ***********************************
    HashMap<Long, BigInteger> aij = new HashMap<>();
    HashMap<Long, BigInteger> gPowAij = new HashMap<>();
    HashMap<Long, ArrayList<BigInteger>> schnorrZKPaij = new HashMap<>();
    HashMap<Long, BigInteger> bij = new HashMap<>();
    HashMap<Long, BigInteger>  gPowBij = new HashMap<>();
    HashMap<Long, ArrayList<BigInteger>> schnorrZKPbij = new HashMap<>();
    BigInteger yi;
    BigInteger gPowYi;
    BigInteger gPowZi;
    ArrayList<BigInteger> schnorrZKPyi = new ArrayList<>();
    String signerID;
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


    BigInteger p = new BigInteger("C196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16);
    BigInteger q = new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16);
    BigInteger g = new BigInteger("A59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16);

    /**
     * Constructs the client by laying out the GUI and registering a
     * listener with the textfield so that pressing Return in the
     * listener sends the textfield contents to the server.  Note
     * however that the textfield is initially NOT editable, and
     * only becomes editable AFTER the client receives the NAMEACCEPTED
     * message from the server.
     */
    public JPAKEPlusClient() {

        // Layout GUI
        textField.setEditable(false);
        messageArea.setEditable(false);
        frame.getContentPane().add(textField, "North");
        frame.getContentPane().add(new JScrollPane(messageArea), "Center");
        frame.pack();

        // Add Listeners
        textField.addActionListener(new ActionListener() {
            /**
             * Responds to pressing the enter key in the textfield by sending
             * the contents of the text field to the server.    Then clear
             * the text area in preparation for the next message.
             */
            public void actionPerformed(ActionEvent e) {
                out.println(textField.getText());
                System.out.println(textField.getText());
                textField.setText("");
            }
        });
    }

    /**
     * Prompt for and return the address of the server.
     */
    private String getServerAddress() {
        return JOptionPane.showInputDialog(
                frame,
                "Enter IP Address of the Server:",
                "JPAKEPlus Proof of Concept",
                JOptionPane.QUESTION_MESSAGE);
    }

    /**
     * Prompt for and return the desired screen name.
     */
    private String getName() {
        return JOptionPane.showInputDialog(
                frame,
                "Choose a screen name:",
                "Screen name selection",
                JOptionPane.PLAIN_MESSAGE);
    }

    private BigInteger spekePlus() {
        try {
            String json = in.readLine();
            RoundZero roundZero = gson.fromJson(json, RoundZero.class);
            SPEKEPlusNetwork speke = new SPEKEPlusNetwork("deadbeef", p, q, g, roundZero.getClientIDs().size(), Long.toString(clientId));
            SpekeRoundOne sRoundOne = speke.roundOne();
            data = gson.toJson(sRoundOne);
            out.println(data);
            response = in.readLine();
            SpekeRoundOneResponse rOneResponse = gson.fromJson(response, SpekeRoundOneResponse.class);

            boolean r1v = speke.verifyRoundOne(rOneResponse);
            if (!r1v) {
                System.exit(0);
            }
            // send confirmation to server
            out.println("1");
            // server can issue go ahead of next stage
            response = in.readLine();
            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }
            SpekeRoundTwo sRoundTwo = speke.roundTwo(rOneResponse);

            out.println(gson.toJson(sRoundTwo));
            // get serialized json of all round 2 calculations
            response = in.readLine();
            SpekeRoundTwoResponse rTwoResponse = gson.fromJson(response, SpekeRoundTwoResponse.class);
            System.out.println(response);
            boolean r2v = speke.verifyRoundTwo(rOneResponse, rTwoResponse);
            if (!r2v) {
                System.out.println("FAILED");
                System.exit(0);
            }
            out.println("1");
            response = in.readLine();
            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }
            BigInteger key = speke.computeKeys(rOneResponse, rTwoResponse);

            return key;
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * Connects to the server then enters the processing loop.
     */
    private void run() throws IOException, ClassNotFoundException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        // Make connection and initialize streams
        String serverAddress = getServerAddress();
        Socket socket = new Socket(serverAddress, 9001);
        in = new BufferedReader(new InputStreamReader(
                socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        RoundZero roundZero = new RoundZero();
        // Process all messages from server, according to the protocol.
        ArrayList<Long> clients = new ArrayList<>();
        while (true) {


            String line = in.readLine();

            System.out.println(" LINE: " + line);

            if (line.startsWith("SUBMITNAME")) {
                clientName = getName();
                out.println(clientName);
            } else if (line.startsWith("NAMEACCEPTED")) {
                clientId = Integer.parseInt(in.readLine());
                textField.setEditable(true);
            } else if (line.startsWith("MESSAGE")) {
                messageArea.append(line.substring(8) + "\n");
            } else if (line.startsWith(":WHO")) {
                String json = in.readLine();
//                clients = gson.fromJson(json, HashSet.class);
//                System.out.println(json);
//                System.out.println(clients.toString());

            } else if (line.startsWith(":START")) {
                String json = in.readLine();
                roundZero = gson.fromJson(json, RoundZero.class);
                System.out.println(json);
                break;
            }
            else if (line.startsWith(":SPEKE")) {
                BigInteger key = spekePlus();
                System.out.println(key.toString(16));
            }
        }
        // round 1

         long cID = (long) clientId;
        clients = roundZero.getClientIDs();
        System.out.println("*************** ROUND 1 ***************");
        int n = clients.size();

        // signerId[i] = i + ""
        signerID = clientId + "";

        // aij in [0, q-1], b_ij in [1, q-1]

        for (int j=0; j<n; j++) {
            System.out.println(clients.get(j) instanceof Long);
            long jID = clients.get(j);
            if (cID==jID){
                continue;
            }

            // aij and ZKP
            aij.put(jID, org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
                    q.subtract(BigInteger.ONE), new SecureRandom()));

            gPowAij.put(jID, g.modPow(aij.get(jID), p));

            schnorrZKP.generateZKP(p, q, g, gPowAij.get(jID), aij.get(jID), signerID);
            schnorrZKPaij.put(jID, new ArrayList<>());
            schnorrZKPaij.get(jID).add(schnorrZKP.getGenPowV());
            schnorrZKPaij.get(jID).add(schnorrZKP.getR());


            // bij and ZKP
            bij.put(jID, org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
                    q.subtract(BigInteger.ONE), new SecureRandom()));

            gPowBij.put(jID, g.modPow(bij.get(jID),p));
            schnorrZKP.generateZKP(p, q, g, gPowBij.get(jID), bij.get(jID), signerID);
            schnorrZKPbij.put(jID, new ArrayList<>());
            schnorrZKPbij.get(jID).add(schnorrZKP.getGenPowV());
            schnorrZKPbij.get(jID).add(schnorrZKP.getR());
        }

        // yi from Zq and ZKP
        yi = (org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
                q.subtract(BigInteger.ONE), new SecureRandom()));

        gPowYi = g.modPow(yi, p);
        signerID = clientId + "";
        schnorrZKP.generateZKP(p, q, g, gPowYi, yi, signerID);
        schnorrZKPyi.add(schnorrZKP.getGenPowV());
        schnorrZKPyi.add(schnorrZKP.getR());


        System.out.println("********** SEND ROUND 1 DATA **********");
        RoundOne dataObject = new RoundOne();
        dataObject.setAij(aij);
        dataObject.setBij(bij);
        dataObject.setgPowAij(gPowAij);
        dataObject.setgPowBij(gPowBij);
        dataObject.setgPowYi(gPowYi);
        dataObject.setgPowZi(gPowZi);
        dataObject.setSchnorrZKPaij(schnorrZKPaij);
        dataObject.setSchnorrZKPbij(schnorrZKPbij);
        dataObject.setSchnorrZKPyi(schnorrZKPyi);
        dataObject.setYi(yi);
        dataObject.setSignerID(signerID);
        data = gson.toJson(dataObject);
        out.println(data);
        response = in.readLine();
        RoundOneResponse rOneResponse = gson.fromJson(response, RoundOneResponse.class);

        // VERIFICATION
        System.out.println("************ VERIFY ROUND 1 ***********");
        for (int i=0; i<n; i++) {

            int iPlusOne = (i==n-1) ? 0: i+1;
            int iMinusOne = (i==0) ? n-1 : i-1;

            long current = Long.parseLong(rOneResponse.getSignerID().get(i));
            long rightNeighbour = Long.parseLong(rOneResponse.getSignerID().get(iPlusOne));
            long leftNeighbour = Long.parseLong(rOneResponse.getSignerID().get(iMinusOne));

            rOneResponse.getgPowZi().put(current, rOneResponse.getgPowYi().get(leftNeighbour).modInverse(p).multiply(rOneResponse.getgPowYi().get(rightNeighbour)).mod(p));

            if(rOneResponse.getgPowZi().get(current).compareTo(BigInteger.ONE) == 0) {
                System.out.println("Round 1 verification failed at checking g^{y_{i+1}}/g^{y_{i-1}}!=1 for i="+i);
            }
        }


        for (int j=0; j<n; j++) {
            long jID = clients.get(j);
            if (cID==jID) {
                continue;
            }

            // Check ZKP{bji}
            if(!verifySchnorrZKP(p, q, g,
                    rOneResponse.getgPowBij().get(jID).get(cID),
                    rOneResponse.getSchnorrZKPbij().get(jID).get(cID).get(0),
                    rOneResponse.getSchnorrZKPbij().get(jID).get(cID).get(1),
                    Long.toString(jID))) {
                out.println(0);
                System.out.println("FAILED 1");
                exitWithError("Round 1 verification failed at checking SchnorrZKP for bij. (i,j)="+"(" + cID + "," +jID + ")");
            }

            // check g^{b_ji} != 1
            if (rOneResponse.getgPowBij().get(jID).get(cID).compareTo(BigInteger.ONE) == 0) {
                out.println("0");
                System.out.println("FAILED 2");
                exitWithError("Round 1 verification failed at checking g^{ji} !=1");
            }

            // Check ZKP{aji}

            if(!verifySchnorrZKP(p, q, g,
                    rOneResponse.getgPowAij().get(jID).get(cID),
                    rOneResponse.getSchnorrZKPaij().get(jID).get(cID).get(0),
                    rOneResponse.getSchnorrZKPaij().get(jID).get(cID).get(1),
                    Long.toString(jID))) {
                out.println("0");
                System.out.println("FAILED 3");
                exitWithError("Round 1 verification failed at checking SchnorrZKP for aij. (i,j)="+"(" + cID + "," + jID + ")");
            }

            // Check ZKP{yi}
            if (!verifySchnorrZKP(p, q, g,
                    rOneResponse.getgPowYi().get(jID),
                    rOneResponse.getSchnorrZKPyi().get(jID).get(0),
                    rOneResponse.getSchnorrZKPyi().get(jID).get(1),
                    Long.toString(jID))) {
                out.println("0");
                System.out.println("FAILED 4");
                exitWithError("Round 1 verification failed at checking SchnorrZKP for yi. (i,j)="+"(" + cID + "," +jID + ")");
            }
        }


        // send confirmation to server
        out.println("1");
        // server can issue go ahead of next stage
        response = in.readLine();
        if (!response.equals("1")) {
            exitWithError("All participants failed to verify Round 1");
        }


        System.out.println("*************** ROUND 2 ***************");

        // Each participant sends newGen^{bij * s} and ZKP{bij * s}
        for (int j=0; j<n; j++) {

            long jID = clients.get(j);
            if (cID==jID){
                continue;
            }

            // g^{a_ij} * g^{a_ji} * g^{b_jj} mod p
            newGen.put(jID,
                    rOneResponse.getgPowAij().get(cID).get(jID)
                    .multiply(rOneResponse.getgPowAij().get(jID).get(cID))
                    .multiply(rOneResponse.getgPowBij().get(jID).get(cID)).mod(p));

            // b_ij * s
            bijs.put(jID, rOneResponse.getBij().get(cID).get(jID).multiply(s).mod(q));

            // (g^{a_ij} * g^{a_ji} * g^{b_jj} mod p)^{b_ij * s}
            newGenPowBijs.put(jID, newGen.get(jID).modPow(bijs.get(jID), p));

            schnorrZKP.generateZKP(p, q, newGen.get(jID), newGenPowBijs.get(jID), bijs.get(jID), signerID);
            schnorrZKPbijs.put(jID, new ArrayList<>());
            schnorrZKPbijs.get(jID).add(schnorrZKP.getGenPowV());
            schnorrZKPbijs.get(jID).add(schnorrZKP.getR());
        }


        RoundTwo dataRoundTwo = new RoundTwo();
        dataRoundTwo.setBijs(bijs);
        dataRoundTwo.setNewGen(newGen);
        dataRoundTwo.setNewGenPowBijs(newGenPowBijs);
        dataRoundTwo.setSchnorrZKPbijs(schnorrZKPbijs);
        dataRoundTwo.setSignerID(signerID);
        // send serialized round two data to server
        out.println(gson.toJson(dataRoundTwo));
        // get serialized json of all round 2 calculations
        response = in.readLine();
        RoundTwoResponse rTwoResponse = gson.fromJson(response, RoundTwoResponse.class);


        System.out.println("************ VERIFY ROUND 2 ***********");

        //             each participant verifies ZKP{bijs}
        for (int j=0; j<n; j++) {
            long jID = clients.get(j);
            if (cID==jID){
                continue;
            }

            // Check ZKP{bji}
            if(!verifySchnorrZKP(p, q,
                    rTwoResponse.getNewGen().get(jID).get(cID),
                    rTwoResponse.getNewGenPowBijs().get(jID).get(cID),
                    rTwoResponse.getSchnorrZKPbijs().get(jID).get(cID).get(0),
                    rTwoResponse.getSchnorrZKPbijs().get(jID).get(cID).get(1),
                    Long.toString(jID)))
                exitWithError("Round 2 verification failed at checking SchnorrZKP for bij. (i,j)="+"(" + clientId + "," + jID + ")");
        }


        // send confirmation to server
        out.println("1");
        // server can issue go ahead of next stage
        response = in.readLine();
        if (!response.equals("1")) {
            exitWithError("All participants failed to verify Round 1");
        }


        System.out.println("*************** ROUND 3 ***************");

        gPowZiPowYi = rOneResponse.getgPowZi().get(cID).modPow(rOneResponse.getYi().get(cID), p);

        ChaumPedersonZKP chaumPedersonZKP = new ChaumPedersonZKP();

        chaumPedersonZKP.generateZKP(p, q, g,
                rOneResponse.getgPowYi().get(cID),
                rOneResponse.getYi().get(cID),
                rOneResponse.getgPowZi().get(cID),
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

            BigInteger rawKey = rOneResponse.getgPowBij().get(jID).get(cID)
                    .modPow(rTwoResponse.getBijs().get(cID).get(jID), p)
                    .modInverse(p)
                    .multiply(rTwoResponse.getNewGenPowBijs().get(jID).get(cID))
                    .modPow(rOneResponse.getBij().get(cID).get(jID), p);

            pairwiseKeysMAC.put(jID, getSHA256(rawKey, "MAC"));
            pairwiseKeysKC.put(jID, getSHA256(rawKey, "KC"));

            // Compute MAC
            String hmacName = "HMac-SHA256";

            try {
                SecretKey key = new SecretKeySpec(pairwiseKeysMAC.get(jID).toByteArray(), hmacName);
                Mac mac = Mac.getInstance(hmacName, "BC");
                mac.init(key);
                mac.update(rOneResponse.getgPowYi().get(cID).toByteArray());
                mac.update(rOneResponse.getSchnorrZKPyi().get(cID).get(0).toByteArray());
                mac.update(rOneResponse.getSchnorrZKPyi().get(cID).get(1).toByteArray());
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

                mac.update(rOneResponse.getgPowAij().get(cID).get(jID).toByteArray());
                mac.update(rOneResponse.getgPowBij().get(cID).get(jID).toByteArray());

                mac.update(rOneResponse.getgPowAij().get(jID).get(cID).toByteArray());
                mac.update(rOneResponse.getgPowBij().get(jID).get(cID).toByteArray());

                hMacsKC.put(jID, new BigInteger(mac.doFinal()));
            } catch(Exception e) {

                e.printStackTrace();
                System.exit(0);

            }
        }

        RoundThree roundThree = new RoundThree();
        roundThree.setChaumPedersonZKPi(chaumPedersonZKPi);
        roundThree.setgPowZiPowYi(gPowZiPowYi);
        roundThree.sethMacsKC(hMacsKC);
        roundThree.sethMacsMAC(hMacsMAC);
        roundThree.setPairwiseKeysKC(pairwiseKeysKC);
        roundThree.setPairwiseKeysMAC(pairwiseKeysMAC);
        out.println(gson.toJson(roundThree));

        response = in.readLine();
        RoundThreeResponse rThreeResponse= gson.fromJson(response, RoundThreeResponse.class);


        System.out.println("*************** ROUND 4 ***************");

            // ith participant
        for (int j=0; j<n; j++) {
            // check ZKP - except ith
            long jID = clients.get(j);
            if (cID==jID) {
                continue;
            }

            if (!verifyChaumPedersonZKP(p, q, g,
                    rOneResponse.getgPowYi().get(jID),
                    rOneResponse.getgPowZi().get(jID),
                    rThreeResponse.getgPowZiPowYi().get(jID),
                    rThreeResponse.getChaumPedersonZKPi().get(jID).get(0),
                    rThreeResponse.getChaumPedersonZKPi().get(jID).get(1),
                    rThreeResponse.getChaumPedersonZKPi().get(jID).get(2),
                    Long.toString(jID))) {
                exitWithError("Round 2 verification failed at checking jth Chaum-Pederson for (i,j)=("+cID+","+jID+")");
            }

            // Check key confirmation - except ith
            String hmacName = "HMac-SHA256";

            if (cID == jID) {
                continue;
            }

            SecretKey key = new SecretKeySpec(rThreeResponse.getPairwiseKeysKC().get(cID).get(jID).toByteArray(), hmacName);

            try {
                Mac mac = Mac.getInstance(hmacName, "BC");
                mac.init(key);

                mac.update("KC".getBytes());
                mac.update(new BigInteger(""+jID).toByteArray());
                mac.update(new BigInteger(""+cID).toByteArray());

                mac.update(rOneResponse.getgPowAij().get(jID).get(cID).toByteArray());
                mac.update(rOneResponse.getgPowBij().get(jID).get(cID).toByteArray());

                mac.update(rOneResponse.getgPowAij().get(cID).get(jID).toByteArray());
                mac.update(rOneResponse.getgPowBij().get(cID).get(jID).toByteArray());
                BigInteger temp = new BigInteger(mac.doFinal());
                System.out.println(temp);
                System.out.println(rThreeResponse.gethMacsKC().get(jID).get(cID));
                if (temp.compareTo(rThreeResponse.gethMacsKC().get(jID).get(cID)) != 0) {
                    exitWithError("Round 3 verification failed at checking KC for (i,j)=("+cID+","+jID+")");
                }
            } catch(Exception e) {
                e.printStackTrace();
                System.exit(0);
            }

            // Check MACs - except ith
            if (cID == jID) {
                continue;
            }

            key = new SecretKeySpec(rThreeResponse.getPairwiseKeysMAC().get(cID).get(jID).toByteArray(), hmacName);

            try {
                Mac mac = Mac.getInstance(hmacName, "BC");
                mac.init(key);
                mac.reset();

                mac.update(rOneResponse.getgPowYi().get(jID).toByteArray());
                mac.update(rOneResponse.getSchnorrZKPyi().get(jID).get(0).toByteArray());
                mac.update(rOneResponse.getSchnorrZKPyi().get(jID).get(1).toByteArray());

                mac.update(rThreeResponse.getgPowZiPowYi().get(jID).toByteArray());
                mac.update(rThreeResponse.getChaumPedersonZKPi().get(jID).get(0).toByteArray());
                mac.update(rThreeResponse.getChaumPedersonZKPi().get(jID).get(1).toByteArray());
                mac.update(rThreeResponse.getChaumPedersonZKPi().get(jID).get(2).toByteArray());

                if (new BigInteger(mac.doFinal()).compareTo(rThreeResponse.gethMacsMAC().get(jID).get(cID)) != 0) {
                    exitWithError("Round 2 verification failed at checking MACs for (i,j)=("+cID+","+jID+")");

                }
            }catch(Exception e){

                e.printStackTrace();
                System.exit(0);

            }
        }


        // send confirmation to server
        out.println("1");
        // server can issue go ahead of next stage
        response = in.readLine();
        if (!response.equals("1")) {
            exitWithError("All participants failed to verify Round 1");
        }


        HashMap<Long, BigInteger> multipleSessionKeys = new HashMap<>();
        System.out.println("*********** KEY COMPUTATION ***********");
//        check yi, gPowYi, gPowZiPowYi generation and storage
        for (int i=0; i<n; i++) {
//            long jID = clients.get(i);
            long iID = clients.get(i);
            // ith participant
//            BigInteger firstTerm = gPowYi[getCyclicIndex(i-1,n)].modPow( yi[i].multiply(BigInteger.valueOf(n)), p);

//        int clientIDIndex = rOneResponse.getSignerID().indexOf(Long.toString(cID));
        int cyclicIndex = getCyclicIndex(i-1, n);
        BigInteger firstTerm = rOneResponse.getgPowYi().get(clients.get(cyclicIndex))
                .modPow(rOneResponse.getYi().get(iID).multiply(BigInteger.valueOf(n)), p);
        BigInteger finalTerm = firstTerm;

        for (int j=0; j<(n-1) ; j++) {
//                int jIDIndex = rOneResponse.getSignerID().indexOf(Long.toString(cID));
//                BigInteger interTerm = gPowZiPowYi[getCyclicIndex(i+j, n)].modPow(BigInteger.valueOf(n-1-j), p);
            cyclicIndex = getCyclicIndex(i+j, n);
            BigInteger interTerm = rThreeResponse.getgPowZiPowYi().get(clients.get(cyclicIndex))
                    .modPow(BigInteger.valueOf(n-1-j), p);
            finalTerm = finalTerm.multiply(interTerm).mod(p);
        }

        multipleSessionKeys.put(clients.get(i), getSHA256(finalTerm));
        sessionKeys =  getSHA256(finalTerm);

        }

        for (int i=0; i<n; i++) {

        System.out.println("Session key " + i + " for client " + clients.get(i) + ": " + multipleSessionKeys.get(clients.get(i)).toString(16));



        }
        out.println("1");
//        }
    }

    /**
     * Runs the client as an application with a closeable frame.
     */
    public static void main(String[] args) throws Exception {
        JPAKEPlusClient client = new JPAKEPlusClient();
        client.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        client.frame.setVisible(true);
        client.run();
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