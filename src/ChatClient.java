package edu.lmu.cs.networking;

import com.google.gson.Gson;
import org.json.simple.JsonObject;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class ChatClient {

    BufferedReader in;
    PrintWriter out;
    Gson gson = new Gson();
    ObjectInputStream objectInputStream;
    JFrame frame = new JFrame("InstantMessenger");
    JTextField textField = new JTextField(40);
    JTextArea messageArea = new JTextArea(8, 40);

    //    BigInteger [][] aij = new BigInteger [n][n];
    ArrayList<ArrayList<BigInteger>> aij = new ArrayList<>();
    //    BigInteger [][] gPowAij = new BigInteger [n][n];
    ArrayList<ArrayList<BigInteger>> gPowAij = new ArrayList<>();
    //    BigInteger [][][] schnorrZKPaij = new BigInteger [n][n][2];
    ArrayList<ArrayList<ArrayList<BigInteger>>> schnorrZKPaij = new ArrayList<>();
    //    BigInteger [][] bij = new BigInteger [n][n];
    ArrayList<ArrayList<BigInteger>> bij = new ArrayList<>();
    //    BigInteger [][] gPowBij = new BigInteger [n][n];
    ArrayList<ArrayList<BigInteger>> gPowBij = new ArrayList<>();
    //    BigInteger [][][] schnorrZKPbij = new BigInteger [n][n][2];
    ArrayList<ArrayList<ArrayList<BigInteger>>> schnorrZKPbij = new ArrayList<>();
    //    BigInteger [] yi = new BigInteger [n];
    ArrayList<BigInteger> yi = new ArrayList<>();
    //    BigInteger [] gPowYi = new BigInteger [n];
    ArrayList<BigInteger> gPowYi = new ArrayList<>();
    //    BigInteger [] gPowZi = new BigInteger [n];
    ArrayList<BigInteger> gPowZi = new ArrayList<>();
    //    BigInteger [][] schnorrZKPyi = new BigInteger [n][2]; // {g^v, r}
    ArrayList<ArrayList<BigInteger>> schnorrZKPyi = new ArrayList<>();
    //    String [] signerID = new String [n];
    ArrayList<String> signerID = new ArrayList<>();
    SchnorrZKP schnorrZKP = new SchnorrZKP();
    /**
     * Constructs the client by laying out the GUI and registering a
     * listener with the textfield so that pressing Return in the
     * listener sends the textfield contents to the server.  Note
     * however that the textfield is initially NOT editable, and
     * only becomes editable AFTER the client receives the NAMEACCEPTED
     * message from the server.
     */
    public ChatClient() {

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
                "Welcome to the Chatter",
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

    /**
     * Connects to the server then enters the processing loop.
     */
    private void run() throws IOException, ClassNotFoundException {

        // Make connection and initialize streams
        String serverAddress = getServerAddress();
        Socket socket = new Socket(serverAddress, 9001);
        in = new BufferedReader(new InputStreamReader(
                socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);

        // Process all messages from server, according to the protocol.
        HashSet<String> clients = new HashSet<>();
        while (true) {


            String line = in.readLine();

            System.out.println(" LINE: " + line);

            if (line.startsWith("SUBMITNAME")) {
                out.println(getName());
            } else if (line.startsWith("NAMEACCEPTED")) {
                textField.setEditable(true);
            } else if (line.startsWith("MESSAGE")) {
                messageArea.append(line.substring(8) + "\n");
            } else if (line.startsWith(":WHO")) {
                String json = in.readLine();
                clients = gson.fromJson(json, HashSet.class);
                System.out.println(json);
                System.out.println(clients.toString());

            } else if (line.startsWith(":START")) {
                break;
            }
        }
        // round 1
        BigInteger p = new BigInteger("C196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16);
        BigInteger q = new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16);
        BigInteger g = new BigInteger("A59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16);

        int n = clients.size();
        for (int i=0; i<n; i++) {

            // signerId[i] = i + ""
            signerID.add(i + "");

            // aij in [0, q-1], b_ij in [1, q-1]
            aij.add(new ArrayList<BigInteger>());
            gPowAij.add(new ArrayList<BigInteger>());
            schnorrZKPaij.add(new ArrayList<>());
            bij.add(new ArrayList<>());
            gPowBij.add(new ArrayList<>());
            schnorrZKPbij.add(new ArrayList<>());
            schnorrZKPyi.add(new ArrayList<>());
            for (int j=0; j<n; j++) {
                schnorrZKPaij.get(i).add(new ArrayList<>());
                schnorrZKPbij.get(i).add(new ArrayList<>());
                if (i==j){
                    continue;
                }

                // aij and ZKP
//                aij[i][j] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
//                        q.subtract(BigInteger.ONE), new SecureRandom());
                aij.get(i).add(org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
                        q.subtract(BigInteger.ONE), new SecureRandom()));

//                gPowAij[i][j] = g.modPow(aij[i][j], p);
                gPowAij.get(i).add(g.modPow(aij.get(i).get(j), p));
                schnorrZKP.generateZKP(p, q, g, gPowAij.get(i).get(j), aij.get(i).get(j), signerID.get(i));
//                schnorrZKPaij[i][j][0] = schnorrZKP.getGenPowV();
                schnorrZKPaij.get(i).get(j).add(schnorrZKP.getGenPowV());
//                schnorrZKPaij[i][j][1] = schnorrZKP.getR();
                schnorrZKPaij.get(i).get(j).add(schnorrZKP.getR());


                // bij and ZKP
//                bij[i][j] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
//                        q.subtract(BigInteger.ONE), new SecureRandom());

                bij.get(i).add(org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
                        q.subtract(BigInteger.ONE), new SecureRandom()));

//                gPowBij[i][j] = g.modPow(bij[i][j], p);
                gPowBij.get(i).add(g.modPow(bij.get(i).get(j),p));
//                schnorrZKP.generateZKP(p, q, g, gPowBij[i][j], bij[i][j], signerID[i]);
                schnorrZKP.generateZKP(p, q, g, gPowBij.get(i).get(j), bij.get(i).get(j), signerID.get(i));
//                schnorrZKPbij[i][j][0] = schnorrZKP.getGenPowV();
                schnorrZKPbij.get(i).get(j).add(schnorrZKP.getGenPowV());
//                schnorrZKPbij[i][j][1] = schnorrZKP.getR();
                schnorrZKPbij.get(i).get(j).add(schnorrZKP.getR());
            }

            // yi from Zq and ZKP
//            yi[i] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
//                    q.subtract(BigInteger.ONE), new SecureRandom());
            yi.add(org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
                    q.subtract(BigInteger.ONE), new SecureRandom()));

//            gPowYi[i] = g.modPow(yi[i], p);
            gPowYi.add(g.modPow(yi.get(i),p));
//            signerID[i] = i + "";
            signerID.set(i, i + "");
//            schnorrZKP.generateZKP(p, q, g, gPowYi[i], yi[i], signerID[i]);
            schnorrZKP.generateZKP(p, q, g, gPowYi.get(i), yi.get(i), signerID.get(i));
//            schnorrZKPyi[i][0] = schnorrZKP.getGenPowV();
            schnorrZKPyi.get(i).add(schnorrZKP.getGenPowV());
//            schnorrZKPyi[i][1] = schnorrZKP.getR();
            schnorrZKPyi.get(i).add(schnorrZKP.getR());
        }

        for (int i=0; i<n; i++) {

            int iPlusOne = (i==n-1) ? 0: i+1;
            int iMinusOne = (i==0) ? n-1 : i-1;

//            gPowZi[i] = gPowYi[iMinusOne].modInverse(p).multiply(gPowYi[iPlusOne]).mod(p);
            gPowZi.add(gPowYi.get(iMinusOne).modInverse(p).multiply(gPowYi.get(iPlusOne).mod(p)));
            if(gPowZi.get(i).compareTo(BigInteger.ONE) == 0) {
                System.out.println("Round 1 verification failed at checking g^{y_{i+1}}/g^{y_{i-1}}!=1 for i="+i);
            }
        }
        String data = gson.toJson(schnorrZKP);
        out.println(data);
        data = gson.toJson(gPowYi);
    }

    /**
     * Runs the client as an application with a closeable frame.
     */
    public static void main(String[] args) throws Exception {
        ChatClient client = new ChatClient();
        client.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        client.frame.setVisible(true);
        client.run();
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