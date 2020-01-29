
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import com.google.gson.Gson;
import org.json.simple.JsonArray;
import org.json.simple.JsonObject;

/**
 *
 *
 */
public class ChatServer {
    /**
     * The port that the server listens on.
     */
    private static final int PORT = 9001;

    /**
     * The set of all names of clients in the chat room.  Maintained
     * so that we can check that new clients are not registering name
     * already in use.
     */
    private static HashSet<HashMap<Long,String>> names = new HashSet<>();
    private static ArrayList<Long> clientIDs = new ArrayList<>();

    private static HashMap<Long, Boolean> roundOneComplete = new HashMap<>();
    private static HashMap<Long, Boolean> roundOneVComplete = new HashMap<>();
    private static HashMap<Long, Boolean> roundTwoComplete = new HashMap<>();
    private static HashMap<Long, Boolean> roundTwoVComplete = new HashMap<>();
    /**
     * The set of all the print writers for all the clients.  This
     * set is kept so we can easily broadcast messages.
     */
    private static HashSet<PrintWriter> writers = new HashSet<PrintWriter>();


    private BigInteger p = new BigInteger("C196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16);
    private BigInteger q = new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16);
    private BigInteger g = new BigInteger("A59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16);

    // ****************************** ROUND 1 ****************************************
    //    BigInteger [][] aij = new BigInteger [n][n];
//        ArrayList<ArrayList<BigInteger>> aij = new ArrayList<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> aij = new HashMap<>();
    //    BigInteger [][] gPowAij = new BigInteger [n][n];
//        ArrayList<ArrayList<BigInteger>> gPowAij = new ArrayList<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> gPowAij = new HashMap<>();
    //    BigInteger [][][] schnorrZKPaij = new BigInteger [n][n][2];
//        ArrayList<ArrayList<ArrayList<BigInteger>>> schnorrZKPaij = new ArrayList<>();
    private static HashMap<Long, HashMap<Long, ArrayList<BigInteger>>> schnorrZKPaij = new HashMap<>();
    //    BigInteger [][] bij = new BigInteger [n][n];
//        ArrayList<ArrayList<BigInteger>> bij = new ArrayList<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> bij = new HashMap<>();
    //    BigInteger [][] gPowBij = new BigInteger [n][n];
    private static HashMap<Long, HashMap<Long, BigInteger>> gPowBij = new HashMap<>();
    //    BigInteger [][][] schnorrZKPbij = new BigInteger [n][n][2];
//        ArrayList<ArrayList<ArrayList<BigInteger>>> schnorrZKPbij = new ArrayList<>();
    private static HashMap<Long, HashMap<Long, ArrayList<BigInteger>>> schnorrZKPbij = new HashMap<>();
    //    BigInteger [] yi = new BigInteger [n];
//        ArrayList<BigInteger> yi = new ArrayList<>();
    private static HashMap<Long, BigInteger> yi = new HashMap<>();
    //    BigInteger [] gPowYi = new BigInteger [n];
//        ArrayList<BigInteger> gPowYi = new ArrayList<>();
    private static HashMap<Long, BigInteger> gPowYi = new HashMap<>();
    //    BigInteger [] gPowZi = new BigInteger [n];
//        ArrayList<BigInteger> gPowZi = new ArrayList<>();
    private static HashMap<Long, BigInteger> gPowZi = new HashMap<>();
    //    BigInteger [][] schnorrZKPyi = new BigInteger [n][2]; // {g^v, r}
//        ArrayList<ArrayList<BigInteger>> schnorrZKPyi = new ArrayList<>();
    private static HashMap<Long, ArrayList<BigInteger>> schnorrZKPyi = new HashMap<>();
    //    String [] signerID = new String [n];
//        ArrayList<String> signerID = new ArrayList<>();
    private static ArrayList<String> signerID = new ArrayList<>();


// ****************************** ROUND 2 ****************************************

    //    BigInteger [][] newGen = new BigInteger [n][n];
//    ArrayList<BigInteger> newGen = new ArrayList<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> newGen = new HashMap<>();
    //    BigInteger [][] bijs = new BigInteger [n][n];
//    ArrayList<BigInteger> bijs = new ArrayList<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> bijs = new HashMap<>();
    //    BigInteger [][] newGenPowBijs = new BigInteger [n][n];
//    ArrayList<BigInteger> newGenPowBijs = new ArrayList<>();;
    private static HashMap<Long, HashMap<Long, BigInteger>> newGenPowBijs = new HashMap<>();
    //    BigInteger [][][] schnorrZKPbijs = new BigInteger [n][n][2];
//    ArrayList<ArrayList<BigInteger>> schnorrZKPbijs = new ArrayList<>();
    private static HashMap<Long, HashMap<Long, ArrayList<BigInteger>>> schnorrZKPbijs = new HashMap<>();



    /**
     * The appplication main method, which just listens on a port and
     * spawns handler threads.
     */
    public static void main(String[] args) throws Exception {
        System.out.println("The chat server is running.");
        ServerSocket listener = new ServerSocket(PORT);
        try {
            while (true) {
                new Handler(listener.accept()).start();
            }
        } finally {
            listener.close();
        }
    }

    /**
     * A handler thread class.  Handlers are spawned from the listening
     * loop and are responsible for a dealing with a single client
     * and broadcasting its messages.
     */
    private static class Handler extends Thread {
        private String name;
        private long id;
        private HashMap<Long, String> idName;
        private Socket socket;
        private BufferedReader in;
        private PrintWriter out;
        private ObjectOutputStream objectOutputStream;
        private Gson gson;
        private String response;


        /**
         * Constructs a handler thread, squirreling away the socket.
         * All the interesting work is done in the run method.
         */
        public Handler(Socket socket) {
            this.socket = socket;
        }

        /**
         * Services this thread's client by repeatedly requesting a
         * screen name until a unique one has been submitted, then
         * acknowledges the name and registers the output stream for
         * the client in a global set, then repeatedly gets inputs and
         * broadcasts them.
         */
        public void run() {
            try {

                // Create character streams for the socket.
                gson = new Gson();
                idName = new HashMap<>();
                id = currentThread().getId();
                roundOneComplete.put(id, false);
                roundOneVComplete.put(id, false);
                roundTwoComplete.put(id, false);
                roundTwoVComplete.put(id, false);
                in = new BufferedReader(new InputStreamReader(
                        socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);
//                objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                // Request a name from this client.  Keep requesting until
                // a name is submitted that is not already used.  Note that
                // checking for the existence of a name and adding the name
                // must be done while locking the set of names.

                while (true) {
                    out.println("SUBMITNAME");
                    name = in.readLine();
                    if (name == null) {
                        return;
                    }
                    idName.put(id, name);
                    synchronized (names) {
                        if (!names.contains(idName)) {
                            names.add(idName);
                            clientIDs.add(currentThread().getId());
                            break;
                        }
                    }

                }

                // Now that a successful name has been chosen, add the
                // socket's print writer to the set of all writers so
                // this client can receive broadcast messages.
                out.println("NAMEACCEPTED");
                out.println(currentThread().getId());
                writers.add(out);
//                objectOutputStream.writeObject(names);

                // Accept messages from this client and broadcast them.
                // Ignore other clients that cannot be broadcasted to.
                System.out.println(currentThread().getId());
                while (true) {
                    String input = in.readLine();

//                    System.out.println(input);
//                    System.out.println(input.equals(":WHO"));
                    if (input == null) {
                        return;
                    }
                    else if (input.equals(":WHO")) {
                        out.println(":WHO");
                        out.println(gson.toJson(names));
                    }
                    else if (input.equals(":START")) {
                        out.println(":START");
                        RoundZero roundZero = new RoundZero();
                        roundZero.setClientIDs(clientIDs);
                        out.println(gson.toJson(roundZero));
                        // round 1
                        response = in.readLine();
                        RoundOne roundOne = gson.fromJson(response, RoundOne.class);
                        System.out.println(roundOne.getSignerID());
                        updateDataRoundOne(id, roundOne);
                        roundOneComplete.replace(id, true);
                        System.out.println(roundOneComplete.toString());
                        while(roundOneComplete.containsValue(false)) { } // busy wait
                        // round 1 verification
                        System.out.println("************ ROUND 1V **********");
                        RoundOneResponse dataRoundOne = setDataRoundOneResponse();
                        out.println(gson.toJson(dataRoundOne));

                        response = in.readLine();
                        if (response.equals("0")) {
                            break;
                        }
                        else {
                            roundOneVComplete.replace(id, true);
                        }
                        System.out.println(roundOneVComplete.toString());
                        while(roundOneVComplete.containsValue(false)) {}
                        // round 2
                        System.out.println("************ ROUND 2 ***********");

                        out.println("1"); // OK

                        // Take in users round two data
                        response = in.readLine();
                        RoundTwo roundTwo = gson.fromJson(response, RoundTwo.class);
                        updateDataRoundTwo(id, roundTwo);
                        roundTwoComplete.replace(id, true);
                        while (roundTwoComplete.containsValue(false)) {}
                        RoundTwoResponse dataRoundTwo = setDataRoundTwoResponse();
                        out.println(gson.toJson(dataRoundTwo));

                        response = in.readLine();
                        if (response.equals("0")) {
                            break;
                        }
                        else {
                            roundTwoVComplete.replace(id, true);
                        }
                        while(roundTwoVComplete.containsValue(false)) {}
                        System.out.println("************ ROUND 3 ***********");

                        out.println("1"); // OK


                        break;
                    }
                    for (PrintWriter writer : writers) {
                        writer.println("MESSAGE " + name + ": " + input);
                    }
                }
                System.out.println("DONE PAIRING");
            } catch (IOException e) {
                System.out.println(e);
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                // This client is going down!  Remove its name and its print
                // writer from the sets, and close its socket.
                if (name != null) {
                    names.remove(name);
                }
                if (out != null) {
                    writers.remove(out);
                }
                try {
                    socket.close();
                } catch (IOException e) {
                }
            }
        }

        public void updateDataRoundOne(Long id, RoundOne data) {
            aij.put(id, data.getAij());
            gPowAij.put(id, data.getgPowAij());
            schnorrZKPaij.put(id, data.getSchnorrZKPaij());
            bij.put(id, data.getBij());
            gPowBij.put(id, data.getgPowBij());
            schnorrZKPbij.put(id, data.getSchnorrZKPbij());
            yi.put(id, data.getYi());
            gPowYi.put(id, data.getgPowYi());
            gPowZi.put(id, data.getgPowZi());
            schnorrZKPyi.put(id, data.getSchnorrZKPyi());
            signerID.add(data.getSignerID());
        }

        public RoundOneResponse setDataRoundOneResponse() {
            RoundOneResponse r = new RoundOneResponse();
            r.setAij(aij);
            r.setgPowAij(gPowAij);
            r.setSchnorrZKPaij(schnorrZKPaij);
            r.setBij(bij);
            r.setgPowBij(gPowBij);
            r.setSchnorrZKPbij(schnorrZKPbij);
            r.setYi(yi);
            r.setgPowYi(gPowYi);
            r.setgPowZi(gPowZi);
            r.setSchnorrZKPyi(schnorrZKPyi);
            r.setSignerID(signerID);
            return r;
        }

        public void updateDataRoundTwo(Long id, RoundTwo data) {
            newGen.put(id, data.getNewGen());
            bijs.put(id, data.getBijs());
            newGenPowBijs.put(id, data.getNewGenPowBijs());
            schnorrZKPbijs.put(id, data.getSchnorrZKPbijs());
            signerID.add(data.getSignerID());
        }

        public RoundTwoResponse setDataRoundTwoResponse() {
            RoundTwoResponse r = new RoundTwoResponse();
            r.setNewGen(newGen);
            r.setBijs(bijs);
            r.setNewGenPowBijs(newGenPowBijs);
            r.setSchnorrZKPbijs(schnorrZKPbijs);
            r.setSignerID(signerID);
            return r;
        }
    }
}