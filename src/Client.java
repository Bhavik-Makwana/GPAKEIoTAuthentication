
import JPAKEPlus.POJOs.*;
import JPAKEPlus.POJOs.POJOs.*;
import JPAKEPlusEllipticCurve.JPAKEPlusECNetwork;
import JPAKEPlusEllipticCurve.POJOs.*;
import SPEKEPlus.POJOs.*;
import SPEKEPlus.POJOs.POJOs.SpekeRoundOne;
import SPEKEPlus.POJOs.POJOs.SpekeRoundOneResponse;
import SPEKEPlus.POJOs.POJOs.SpekeRoundTwo;
import SPEKEPlus.POJOs.POJOs.SpekeRoundTwoResponse;
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
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class Client {
    long startTime = 0;
    long endTime = 0;
    BufferedReader in;
    PrintWriter out;
    Gson gson = new Gson();
    JFrame frame = new JFrame("Client");
    JTextField textField = new JTextField(40);
    JTextArea messageArea = new JTextArea(8, 40);
    String clientName;
    String data;
    String response;
    String sStr = "deadbeef";

    int clientId;

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
    public Client() {

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
            SpekeRoundOne roundOne = speke.roundOne();
            data = gson.toJson(roundOne);
            out.println(data);
            response = in.readLine();
            SpekeRoundOneResponse rOneResponse = gson.fromJson(response, SpekeRoundOneResponse.class);

            boolean passedRoundOne= speke.verifyRoundOne(rOneResponse);
            if (!passedRoundOne) {
                System.exit(0);
            }
            // send confirmation to server
            out.println("1");
            // server can issue go ahead of next stage
            response = in.readLine();
            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }
            SpekeRoundTwo roundTwo = speke.roundTwo(rOneResponse);

            out.println(gson.toJson(roundTwo));
            // get serialized json of all round 2 calculations
            response = in.readLine();
            SpekeRoundTwoResponse rTwoResponse = gson.fromJson(response, SpekeRoundTwoResponse.class);
            boolean passedRoundTwo = speke.verifyRoundTwo(rOneResponse, rTwoResponse);
            if (!passedRoundTwo) {
                System.out.println("FAILED");
                System.exit(0);
            }
            out.println("1");
            response = in.readLine();
            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }
            BigInteger key = speke.computeKeys(rOneResponse, rTwoResponse);
            speke.displayLatency();
            return key;
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private BigInteger jpakePlus() {
        try {

            String json = in.readLine();
            RoundZero roundZero = gson.fromJson(json, RoundZero.class);
            ArrayList<Long> clients =  roundZero.getClientIDs();
            JPAKEPlusNetwork jpake= new JPAKEPlusNetwork("deadbeef", p, q, g, roundZero.getClientIDs().size(), Long.toString(clientId), clients, clientId);
            RoundOne roundOne = jpake.roundOne();
            data = gson.toJson(roundOne);
            startTime = System.currentTimeMillis();
            out.println(data);
            response = in.readLine();
            endTime = System.currentTimeMillis();
            System.out.println("1) Latency of retrieving round one response from server (ms):" + (endTime-startTime));
            RoundOneResponse rOneResponse = gson.fromJson(response, RoundOneResponse.class);

            boolean passedRoundOne = jpake.verifyRoundOne(rOneResponse);
            if (!passedRoundOne) {
                out.println("0");
                System.exit(0);
            }
            // send confirmation to server
            startTime = System.currentTimeMillis();
            out.println("1");
            // server can issue go ahead of next stage
            response = in.readLine();
            endTime = System.currentTimeMillis();
            System.out.println("1) Latency of getting OK after round one verification from server (ms):" + (endTime-startTime));

            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }

            RoundTwo roundTwo = jpake.roundTwo(rOneResponse);

            startTime = System.currentTimeMillis();
            // send serialized round two data to server
            out.println(gson.toJson(roundTwo));
            // get serialized json of all round 2 calculations
            response = in.readLine();
            endTime = System.currentTimeMillis();
            System.out.println("1) Latency of retrieving round two response from server (ms):" + (endTime-startTime));
            RoundTwoResponse rTwoResponse = gson.fromJson(response, RoundTwoResponse.class);

            boolean passedRoundTwo = jpake.verifyRoundTwo(rTwoResponse);
            if (!passedRoundTwo) {
                System.out.println("FAILED");
                System.exit(0);
            }

            startTime = System.currentTimeMillis();
            // send confirmation to server
            out.println("1");
            // server can issue go ahead of next stage
            response = in.readLine();
            endTime = System.currentTimeMillis();
            System.out.println("1) Latency of getting OK after round two verification from server (ms):" + (endTime-startTime));

            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }

            RoundThree roundThree = jpake.roundThree(rOneResponse, rTwoResponse);

            startTime = System.currentTimeMillis();
            out.println(gson.toJson(roundThree));
            response = in.readLine();
            RoundThreeResponse rThreeResponse = gson.fromJson(response, RoundThreeResponse.class);
            endTime = System.currentTimeMillis();
            System.out.println("1) Latency of retrieving round three response from server (ms):" + (endTime-startTime));
            boolean passedRoundThree = jpake.roundFour(rOneResponse, rTwoResponse, rThreeResponse);
            if (!passedRoundThree) {
                exitWithError("All paricipants failed to verify round 3");
            }
            startTime = System.currentTimeMillis();

            // send confirmation to server
            out.println("1");
            // server can issue go ahead of next stage
            response = in.readLine();
            endTime = System.currentTimeMillis();
            System.out.println("1) Latency of retrieving OK after round 3 verificationfrom server (ms):" + (endTime-startTime));

            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }


            BigInteger key = jpake.computeKey(rOneResponse, rThreeResponse);
            out.println("1");

            jpake.displayLatency();
            return key;
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private BigInteger jpakePlusEC() {
        try {

            String json = in.readLine();
            RoundZero roundZero = gson.fromJson(json, RoundZero.class);
            ArrayList<Long> clients =  roundZero.getClientIDs();
            JPAKEPlusECNetwork jpake = new JPAKEPlusECNetwork("deadbeef", roundZero.getClientIDs().size(), Long.toString(clientId), clients, clientId);
            ECRoundOne roundOne = jpake.roundOne();
            data = gson.toJson(roundOne);
            System.out.println("Ggg");
            out.println(data);
            response = in.readLine();
            ECRoundOneResponse rOneResponse = gson.fromJson(response, ECRoundOneResponse.class);

            boolean passedRoundOne = jpake.verifyRoundOne(rOneResponse);
            if (!passedRoundOne) {
                out.println("0");
                System.exit(0);
            }
            // send confirmation to server
            out.println("1");
            // server can issue go ahead of next stage
            response = in.readLine();
            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }

            ECRoundTwo roundTwo = jpake.roundTwo(rOneResponse);
            // send serialized round two data to server
            out.println(gson.toJson(roundTwo));
            // get serialized json of all round 2 calculations
            response = in.readLine();
            ECRoundTwoResponse rTwoResponse = gson.fromJson(response, ECRoundTwoResponse.class);

            boolean passedRoundTwo = jpake.verifyRoundTwo(rTwoResponse);
            if (!passedRoundTwo) {
                System.out.println("FAILED");
                System.exit(0);
            }
            // send confirmation to server
            out.println("1");
            // server can issue go ahead of next stage
            response = in.readLine();
            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }

            ECRoundThree roundThree = jpake.roundThree(rOneResponse, rTwoResponse);
            out.println(gson.toJson(roundThree));

            response = in.readLine();
            ECRoundThreeResponse rThreeResponse = gson.fromJson(response, ECRoundThreeResponse.class);

            boolean passedRoundThree = jpake.roundFour(rOneResponse, rTwoResponse, rThreeResponse);
            if (!passedRoundThree) {
                exitWithError("All paricipants failed to verify round 3");
            }

            // send confirmation to server
            out.println("1");
            // server can issue go ahead of next stage
            response = in.readLine();
            if (!response.equals("1")) {
                exitWithError("All participants failed to verify Round 1");
            }


            BigInteger key = jpake.computeKey(rOneResponse, rThreeResponse);
            out.println("1");

            jpake.displayLatency();
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
        Socket socket = new Socket(serverAddress, 8080);
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

            } else if (line.startsWith(":EC")) {
                BigInteger key = jpakePlusEC();
                System.out.println(key.toString(16));
                break;
            } else if (line.startsWith(":START")) {
                BigInteger key = jpakePlus();
                System.out.println(key.toString(16));
                break;
            }
            else if (line.startsWith(":SPEKE")) {
                BigInteger key = spekePlus();
                System.out.println(key.toString(16));
            }
            else {
                break;
            }
        }

    }

    /**
     * Runs the client as an application with a closeable frame.
     */
    public static void main(String[] args) throws Exception {
        Client client = new Client();
        client.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        client.frame.setVisible(true);
        client.run();
    }




    public void exitWithError(String s){
        System.out.println("Exit with ERROR: " + s);
        System.exit(0);
    }

}