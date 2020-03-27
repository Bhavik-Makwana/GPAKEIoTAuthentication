
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import JPAKEPlus.POJOs.POJOs.*;
import JPAKEPlusEllipticCurve.POJOs.*;
import JPAKEPlusEllipticCurve.ZKPs.ChaumPedersonZKP;
import JPAKEPlusEllipticCurve.ZKPs.SchnorrZKP;
import SPEKEPlus.POJOs.POJOs.SpekeRoundOne;
import SPEKEPlus.POJOs.POJOs.SpekeRoundOneResponse;
import SPEKEPlus.POJOs.POJOs.SpekeRoundTwo;
import SPEKEPlus.POJOs.POJOs.SpekeRoundTwoResponse;
import com.google.gson.Gson;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound1Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound2Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound3Payload;

/**
 *
 *
 */
public class Server {
    /**
     * The port that the server listens on.
     */
    private static final int PORT = 8002;

    /**
     * The set of all names of clients in the chat room.  Maintained
     * so that we can check that new clients are not registering name
     * already in use.
     */
    private static HashSet<HashMap<Long, String>> names = new HashSet<>();
    private static ArrayList<Long> clientIDs = new ArrayList<>();
    private static HashMap<Long, PrintWriter> clients = new HashMap<>();

    private static HashMap<Long, Boolean> roundOneComplete = new HashMap<>();
    private static HashMap<Long, Boolean> roundOneVComplete = new HashMap<>();
    private static HashMap<Long, Boolean> roundTwoComplete = new HashMap<>();
    private static HashMap<Long, Boolean> roundTwoVComplete = new HashMap<>();
    private static HashMap<Long, Boolean> roundThreeComplete = new HashMap<>();
    private static HashMap<Long, Boolean> roundFourComplete = new HashMap<>();

    private static HashMap<Long, Boolean> JPAKEroundOneComplete = new HashMap<>();
    private static HashMap<Long, Boolean> JPAKEroundOneVComplete = new HashMap<>();
    private static HashMap<Long, Boolean> JPAKEroundTwoComplete = new HashMap<>();
    private static HashMap<Long, Boolean> JPAKEroundTwoVComplete = new HashMap<>();
    private static HashMap<Long, Boolean> JPAKEroundThreeComplete = new HashMap<>();
    private static HashMap<Long, Boolean> JPAKEroundFourComplete = new HashMap<>();
    /**
     * The set of all the print writers for all the clients.  This
     * set is kept so we can easily broadcast messages.
     */
    private static HashSet<PrintWriter> writers = new HashSet<PrintWriter>();

    // ****************************** ROUND 1 ****************************************
//    private static HashMap<Long, HashMap<Long, BigInteger>> aij = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> gPowAij = new HashMap<>();
    private static HashMap<Long, HashMap<Long, ArrayList<BigInteger>>> schnorrZKPaij = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> bij = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> gPowBij = new HashMap<>();
    private static HashMap<Long, HashMap<Long, ArrayList<BigInteger>>> schnorrZKPbij = new HashMap<>();
    private static HashMap<Long, BigInteger> yi = new HashMap<>();
    private static HashMap<Long, BigInteger> gPowYi = new HashMap<>();
    private static HashMap<Long, BigInteger> gPowZi = new HashMap<>();
    private static HashMap<Long, ArrayList<BigInteger>> schnorrZKPyi = new HashMap<>();
    private static ArrayList<String> signerID = new ArrayList<>();


// ****************************** ROUND 2 ****************************************

    private static HashMap<Long, HashMap<Long, BigInteger>> newGen = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> bijs = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> newGenPowBijs = new HashMap<>();
    private static HashMap<Long, HashMap<Long, ArrayList<BigInteger>>> schnorrZKPbijs = new HashMap<>();

    // ****************************** ROUND 3 ****************************************
    private static HashMap<Long, BigInteger> gPowZiPowYi = new HashMap<>();
    private static HashMap<Long, ArrayList<BigInteger>> chaumPedersonZKPi = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> pairwiseKeysMAC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> pairwiseKeysKC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> hMacsMAC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> hMacsKC = new HashMap<>();




    private static HashMap<Long, BigInteger> xiSpeke = new HashMap<>();
    private static HashMap<Long, BigInteger> yiSpeke = new HashMap<>();
    private static HashMap<Long, BigInteger> gsPowXiSpeke = new HashMap<>();
    private static HashMap<Long, BigInteger> gPowYiSpeke = new HashMap<>();
    private static HashMap<Long, BigInteger> gPowZiSpeke = new HashMap<>();
    private static HashMap<Long, ArrayList<BigInteger>> schnorrZKPiSpeke = new HashMap<>();
    private static ArrayList<String> signerIDSpeke = new ArrayList<>();


    private static HashMap<Long, BigInteger> gPowZiPowYiSpeke = new HashMap<>();
    private static HashMap<Long, ArrayList<BigInteger>> chaumPedersonZKPiSpeke = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> pairwiseKeysMACSpeke = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> pairwiseKeysKCSpeke = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> hMacsMACSpeke = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> hMacsKCSpeke = new HashMap<>();


    // ********************************* ROUND 1 EC **********************************
    private  static HashMap<Long, HashMap<Long, BigInteger>> aijEC = new HashMap<>();
    private  static HashMap<Long, HashMap<Long, byte[]>> gPowAijEC = new HashMap<>();
    private  static HashMap<Long, HashMap<Long, SchnorrZKP>> schnorrZKPaijEC = new HashMap<>();
    private  static HashMap<Long, HashMap<Long, BigInteger>> bijEC = new HashMap<>();
    private  static HashMap<Long, HashMap<Long, byte[]>> gPowBijEC = new HashMap<>();
    private  static HashMap<Long, HashMap<Long, SchnorrZKP>> schnorrZKPbijEC = new HashMap<>();
    private  static HashMap<Long, BigInteger> yiEC = new HashMap<>();
    private  static HashMap<Long, byte[]> gPowYiEC = new HashMap<>();
    private  static HashMap<Long, byte[]> gPowZiEC = new HashMap<>();
    private  static HashMap<Long, SchnorrZKP> schnorrZKPyiEC = new HashMap<>();
//    private  static ArrayList<String> signerID = new ArrayList<>();

// ********************************** ROUND 2 EC ************************************
    private static HashMap<Long, HashMap<Long, byte[]>> newGenEC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> bijsEC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, byte[]>> newGenPowBijsEC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, SchnorrZKP>> schnorrZKPbijsEC = new HashMap<>();

// ********************************** ROUND 3 EC ************************************
    private static HashMap<Long, byte[]> gPowZiPowYiEC = new HashMap<>();
    private static HashMap<Long, ChaumPedersonZKP> chaumPedersonZKPiEC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> pairwiseKeysMACEC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> pairwiseKeysKCEC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> hMacsMACEC = new HashMap<>();
    private static HashMap<Long, HashMap<Long, BigInteger>> hMacsKCEC = new HashMap<>();

    // ********************************** JPAKE ************************************
    private static HashMap<Long, JPAKERound1Payload> jpakeRoundOne = new HashMap<>();
    private static HashMap<Long, JPAKERound2Payload> jpakeRoundTwo = new HashMap<>();
    private static HashMap<Long, JPAKERound3Payload> jpakeRoundThree = new HashMap<>();

    private static boolean groupMade = false;
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
        private Gson gson;
        private String response;


        /**
         * Constructor, makes a handler thread establishing the socket
         * to connect on. Allowing a thread to deal with each instance
         * of a client.
         *
         * @param  socket  socket server will be listening on
         */
        public Handler(Socket socket) {
            this.socket = socket;
        }

        /**
         * Services this thread's client by repeatedly requesting a
         * screen name until a unique one has been submitted, then
         * acknowledges the name and registers the output stream for
         * the client in a global set. After this it listens on the
         * port to either chat or start a key exchange protocol.
         */
        public void run() {
            try {
                gson = new Gson();
                idName = new HashMap<>();
                id = currentThread().getId();
                roundOneComplete.put(id, false);
                roundOneVComplete.put(id, false);
                roundTwoComplete.put(id, false);
                roundTwoVComplete.put(id, false);
                roundThreeComplete.put(id, false);
                roundFourComplete.put(id, false);
                in = new BufferedReader(new InputStreamReader(
                        socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

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
                            clients.put(currentThread().getId(), out);
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

                // Accept messages from this client and broadcast them.
                // Ignore other clients that cannot be broadcasted to.
                System.out.println(currentThread().getId());
                while (true) {
                    String input = in.readLine();
                    System.out.println("input " + input);
                    if (input == null) {
                        return;
                    } else if (input.equals(":WHO")) {
                        out.println(":WHO");
                        out.println(gson.toJson(names));
                    } else if (input.equals(":START")) {
                        jPAKEPlusProtocol();
                        groupMade = true;

                    }
                    else if (input.equals(":REMOVE")) {
                        jPAKEPlusProtocol();
                        groupMade = true;

                    }
                    else if (input.equals(":EC")) {
                        jPAKEPlusECProtocol();
                        groupMade = true;

                    }
                    else if (input.equals(":SPEKE")) {
                        sPEKEPlusProtocol();
                        groupMade = true;
                    }
                    else if (input.equals(":PAIR")) {
                        System.out.println(":PAIR");
                        addNewClient(false);
                    }
                    else if (input.equals(":PARTNER")) {
                        System.out.println(":PARTNER");
                        addNewClient(true);
                    }
//                    for (PrintWriter writer : writers) {
//                        writer.println("MESSAGE " + name + ": " + input);
//                    }
                }
//                System.out.println("DONE PAIRING");

            } catch (IOException e) {
                System.out.println(e);
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                // This client is going down!  Remove its name and its print
                // writer from the sets, and close its socket.
                if (name != null) {
                    names.remove(idName);
                }
                if (out != null) {
                    writers.remove(out);
                }
                clientIDs.remove(id);
                try {
                    socket.close();
                } catch (IOException e) {
                }
                roundOneComplete.remove(id);
                roundOneVComplete.remove(id);
                roundTwoComplete.remove(id);
                roundTwoVComplete.remove(id);
                roundThreeComplete.remove(id);
                roundFourComplete.remove(id);
                System.out.println("Remove User");
                removeUser(id);
                System.out.println(names.toString());
                System.out.println(clientIDs.toString());
                System.out.println(writers.toString());
            }
        }

        public void addNewClient(boolean partner) {
            try {
                if (groupMade) {
                    //  pick random client in group
                    if (partner) {
                        ArrayList<Long> pairwiseClients = new ArrayList<>();
                        Long joiningClient = Long.parseLong(in.readLine());
                        pairwiseClients.add(joiningClient);
                        pairwiseClients.add(currentThread().getId());
                        System.out.println(pairwiseClients.toString());
                        jPAKEProtocol(pairwiseClients);
                        System.out.println("Sending 1 to: " + pairwiseClients.get(1));
                        clients.get(pairwiseClients.get(1)).println("1");
                        System.out.println("Got key");
                        response = in.readLine();
                        System.out.println("response " + response);
                        while (response == null) {
                            response = in.readLine();
                            System.out.println("response " + response);
                        }
                        System.out.println("Sending key to requester "+ pairwiseClients.get(0) + ": " + response);
                        clients.get(pairwiseClients.get(0)).println(response);
                    }
                    else {
                        ArrayList<Long> pairwiseClients = new ArrayList<>();
                        pairwiseClients.add(currentThread().getId());
                        pairwiseClients.add(clientIDs.get(0));
                        clients.get(pairwiseClients.get(1)).println(":PARTNER");
                        clients.get(pairwiseClients.get(1)).println(currentThread().getId());
                        jPAKEProtocol(pairwiseClients);
//                        clients.get(currentThread().getId()).println(gro);
                    }

                    //  perform jpake protocol
                    //  send group key

                } else {
//                    jPAKEPlusECProtocol();
                    System.out.println("No pre-existing group established, please set up first");
                }
            }
            catch (Exception e) {
                e.printStackTrace();;
            }
        }

        public void removeUser(Long id) {
            for (Long i :clientIDs) {
                roundOneComplete.replace(i, false);
                roundOneVComplete.replace(i, false);
                roundTwoComplete.replace(i, false);
                roundTwoVComplete.replace(i, false);
                roundThreeComplete.replace(i, false);
                roundFourComplete.replace(i, false);
            }

            JPAKEroundOneComplete = new HashMap<>();
            JPAKEroundOneVComplete = new HashMap<>();
            JPAKEroundTwoComplete = new HashMap<>();
            JPAKEroundTwoVComplete = new HashMap<>();
            JPAKEroundThreeComplete = new HashMap<>();
            JPAKEroundFourComplete = new HashMap<>();

            // ****************************** ROUND 1 ****************************************
            gPowAij = new HashMap<>();
            schnorrZKPaij = new HashMap<>();
            bij = new HashMap<>();
            gPowBij = new HashMap<>();
            schnorrZKPbij = new HashMap<>();
            yi = new HashMap<>();
            gPowYi = new HashMap<>();
            gPowZi = new HashMap<>();
            schnorrZKPyi = new HashMap<>();
            signerID = new ArrayList<>();


// ****************************** ROUND 2 ****************************************

             newGen = new HashMap<>();
             bijs = new HashMap<>();
             newGenPowBijs = new HashMap<>();
             schnorrZKPbijs = new HashMap<>();

            // ****************************** ROUND 3 ****************************************
             gPowZiPowYi = new HashMap<>();
            chaumPedersonZKPi = new HashMap<>();
             pairwiseKeysMAC = new HashMap<>();
             pairwiseKeysKC = new HashMap<>();
             hMacsMAC = new HashMap<>();
             hMacsKC = new HashMap<>();




             xiSpeke = new HashMap<>();
             yiSpeke = new HashMap<>();
             gsPowXiSpeke = new HashMap<>();
             gPowYiSpeke = new HashMap<>();
             gPowZiSpeke = new HashMap<>();
            schnorrZKPiSpeke = new HashMap<>();
            signerIDSpeke = new ArrayList<>();


             gPowZiPowYiSpeke = new HashMap<>();
            chaumPedersonZKPiSpeke = new HashMap<>();
             pairwiseKeysMACSpeke = new HashMap<>();
             pairwiseKeysKCSpeke = new HashMap<>();
             hMacsMACSpeke = new HashMap<>();
             hMacsKCSpeke = new HashMap<>();


            // ********************************* ROUND 1 EC **********************************
            aijEC = new HashMap<>();
             gPowAijEC = new HashMap<>();
             schnorrZKPaijEC = new HashMap<>();
            bijEC = new HashMap<>();
            gPowBijEC = new HashMap<>();
            schnorrZKPbijEC = new HashMap<>();
            yiEC = new HashMap<>();
            gPowYiEC = new HashMap<>();
            gPowZiEC = new HashMap<>();
            schnorrZKPyiEC = new HashMap<>();
//    private  static ArrayList<String> signerID = new ArrayList<>();

// ********************************** ROUND 2 EC ************************************
            newGenEC = new HashMap<>();
             bijsEC = new HashMap<>();
            newGenPowBijsEC = new HashMap<>();
            schnorrZKPbijsEC = new HashMap<>();

// ********************************** ROUND 3 EC ************************************
            gPowZiPowYiEC = new HashMap<>();
             chaumPedersonZKPiEC = new HashMap<>();
             pairwiseKeysMACEC = new HashMap<>();
             pairwiseKeysKCEC = new HashMap<>();
             hMacsMACEC = new HashMap<>();
             hMacsKCEC = new HashMap<>();

            // ********************************** JPAKE ************************************
            jpakeRoundOne = new HashMap<>();
            jpakeRoundTwo = new HashMap<>();
            jpakeRoundThree = new HashMap<>();

            groupMade = false;


            for (Map.Entry<Long, PrintWriter> p : clients.entrySet()) {
                p.getValue().println(":REMOVE");
            }
        }
        /**
         * Update the servers global bulletin board of data associated with
         * each user with the data collected at round 1.
         *
         * @param  id   ID of the client
         * @param  data Data collected from the first round of JPAKE+
         */
        public void updatePairDataRoundOne(Long id, JPAKERound1Payload data) {
            jpakeRoundOne.put(id, data);
        }

        public void updatePairDataRoundTwo(Long id, JPAKERound2Payload data) {
            jpakeRoundTwo.put(id, data);
        }

        public void updatePairDataRoundThree(Long id, JPAKERound3Payload data) {
            jpakeRoundThree.put(id, data);
        }

        public void jPAKEProtocol(ArrayList<Long> pairwiseClients) throws Exception {

            JPAKEroundOneComplete.put(pairwiseClients.get(0), false);
            JPAKEroundOneComplete.put(pairwiseClients.get(1), false);

            JPAKEroundOneVComplete.put(pairwiseClients.get(0), false);
            JPAKEroundOneVComplete.put(pairwiseClients.get(1), false);

            JPAKEroundTwoComplete.put(pairwiseClients.get(0), false);
            JPAKEroundTwoComplete.put(pairwiseClients.get(1), false);

            JPAKEroundTwoVComplete.put(pairwiseClients.get(0), false);
            JPAKEroundTwoVComplete.put(pairwiseClients.get(1), false);

            JPAKEroundThreeComplete.put(pairwiseClients.get(0), false);
            JPAKEroundThreeComplete.put(pairwiseClients.get(1), false);

            JPAKEroundFourComplete.put(pairwiseClients.get(0), false);
            JPAKEroundFourComplete.put(pairwiseClients.get(1), false);

            try {

                out.println(":PAIR");
                RoundZero roundZero = new RoundZero();


                roundZero.setClientIDs(pairwiseClients);
                out.println(gson.toJson(roundZero));
                // round 1
                response = in.readLine();
                System.out.println(response);
                JPAKERound1Payload roundOne = gson.fromJson(response, JPAKERound1Payload.class);
                updatePairDataRoundOne(id, roundOne);
                JPAKEroundOneComplete.replace(id, true);


                System.out.println(JPAKEroundOneComplete.toString());
                while (JPAKEroundOneComplete.containsValue(false)) {
                } // busy wait
                System.out.println("************ ROUND 1V **********");
                JPAKE.RoundOne roundOneResponse = new JPAKE.RoundOne();
                roundOneResponse.setJpakeRoundOne(jpakeRoundOne);
                out.println(gson.toJson(roundOneResponse));

                response = in.readLine();
                if (response.equals("0")) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    JPAKEroundOneVComplete.replace(id, true);
                }
                System.out.println(JPAKEroundOneVComplete.toString());
                while (JPAKEroundOneVComplete.containsValue(false)) {
                }
                // round 2
                System.out.println("************ ROUND 2 ***********");

                out.println("1"); // OK

                // Take in users round two data
                response = in.readLine();
                JPAKERound2Payload roundTwo = gson.fromJson(response, JPAKERound2Payload.class);
                updatePairDataRoundTwo(id, roundTwo);
                JPAKEroundTwoComplete.replace(id, true);
                while (JPAKEroundTwoComplete.containsValue(false)) {
                }
                System.out.println("*********** ROUND 2V ***********");
                JPAKE.RoundTwo roundTwoResponse = new JPAKE.RoundTwo();
                roundTwoResponse.setJpakeRoundTwo(jpakeRoundTwo);
                out.println(gson.toJson(roundTwoResponse));


                response = in.readLine();
                if (response.equals("0")) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    JPAKEroundTwoVComplete.replace(id, true);
                }
                while (JPAKEroundTwoVComplete.containsValue(false)) {
                }
                System.out.println("************ ROUND 3 ***********");

                out.println("1"); // OK

                response = in.readLine();
                JPAKERound3Payload roundThree = gson.fromJson(response, JPAKERound3Payload.class);
                updatePairDataRoundThree(id, roundThree);
                JPAKEroundThreeComplete.replace(id, true);
                while (JPAKEroundThreeComplete.containsValue(false)) {
                }
                System.out.println("************ ROUND 4 ***********");
                JPAKE.RoundThree roundThreeResponse = new JPAKE.RoundThree();
                roundThreeResponse.setJpakeRoundThree(jpakeRoundThree);
                out.println(gson.toJson(roundThreeResponse));

                response = in.readLine();

                if (response.equals(0)) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    JPAKEroundFourComplete.replace(id, true);
                }
                while (JPAKEroundFourComplete.containsValue(false)) {
                }
                System.out.println("******* KEY COMPUTATION *******");
                out.println("1");

                response = in.readLine();
                System.out.println("confirmation response: " + response);
                if (response.equals("1")) {
                    System.out.println("Session Keys Computed");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }



        /**
         * Update the servers global bulletin board of data associated with
         * each user with the data collected at round 1.
         *
         * @param  id   ID of the client
         * @param  data Data collected from the first round of JPAKE+
         * @return      the image at the specified URL
         */
        public void updateDataRoundOne(Long id, RoundOne data) {
//            aij.put(id, data.getAij());
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

        /**
         * Returns a POJO containing all the data gathered after round one.
         *
         * @return      the data generated by all clients in round 1
         */
        public RoundOneResponse setDataRoundOneResponse() {
            RoundOneResponse r = new RoundOneResponse();
//            r.setAij(aij);
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

        /**
         * Update the servers global bulletin board of data associated with
         * each user with the data collected at round 2.
         *
         * @param  id   ID of the client
         * @param  data Data collected from the first round of JPAKE+
         * @return      the image at the specified URL
         */
        public void updateDataRoundTwo(Long id, RoundTwo data) {
            newGen.put(id, data.getNewGen());
            bijs.put(id, data.getBijs());
            newGenPowBijs.put(id, data.getNewGenPowBijs());
            schnorrZKPbijs.put(id, data.getSchnorrZKPbijs());
            signerID.add(data.getSignerID());
        }

        /**
         * Returns a POJO containing all the data gathered after round 2.
         *
         * @return      the data generated by all clients in round one
         */
        public RoundTwoResponse setDataRoundTwoResponse() {
            RoundTwoResponse r = new RoundTwoResponse();
            r.setNewGen(newGen);
            r.setBijs(bijs);
            r.setNewGenPowBijs(newGenPowBijs);
            r.setSchnorrZKPbijs(schnorrZKPbijs);
            r.setSignerID(signerID);
            return r;
        }

        /**
         * Update the servers global bulletin board of data associated with
         * each user with the data collected at round 3.
         *
         * @param  id   ID of the client
         * @param  data Data collected from the first round of JPAKE+
         * @return      the image at the specified URL
         */
        public void updateDataRoundThree(Long id, RoundThree data) {
            gPowZiPowYi.put(id, data.getgPowZiPowYi());
            chaumPedersonZKPi.put(id, data.getChaumPedersonZKPi());
            pairwiseKeysKC.put(id, data.getPairwiseKeysKC());
            pairwiseKeysMAC.put(id, data.getPairwiseKeysMAC());
            hMacsKC.put(id, data.gethMacsKC());
            hMacsMAC.put(id, data.gethMacsMAC());
        }

        /**
         * Returns a POJO containing all the data gathered after round one.
         *
         * @return      the data generated by all clients in round 3
         */
        public RoundThreeResponse setDataRoundThreeResponse() {
            RoundThreeResponse r = new RoundThreeResponse();
            r.setChaumPedersonZKPi(chaumPedersonZKPi);
            r.setgPowZiPowYi(gPowZiPowYi);
            r.sethMacsKC(hMacsKC);
            r.sethMacsMAC(hMacsMAC);
            r.setPairwiseKeysKC(pairwiseKeysKC);
            r.setPairwiseKeysMAC(pairwiseKeysMAC);
            return r;
        }

        public void resetKeys() {
            roundOneComplete = new HashMap<>();
            roundOneVComplete = new HashMap<>();
            roundTwoComplete = new HashMap<>();
            roundTwoVComplete = new HashMap<>();
            roundThreeComplete = new HashMap<>();
            roundFourComplete = new HashMap<>();
            roundOneComplete.put(id, false);
            roundOneVComplete.put(id, false);
            roundTwoComplete.put(id, false);
            roundTwoVComplete.put(id, false);
            roundThreeComplete.put(id, false);
            roundFourComplete.put(id, false);
//            aij = new HashMap<>();
//            gPowAij = new HashMap<>();
//            schnorrZKPaij = new HashMap<>();
//            bij = new HashMap<>();
//            gPowBij = new HashMap<>();
//            schnorrZKPbij = new HashMap<>();
//            yi = new HashMap<>();
//            gPowYi = new HashMap<>();
//            gPowZi = new HashMap<>();
//            schnorrZKPyi = new HashMap<>();
//            signerID = new ArrayList<>();
//            newGen = new HashMap<>();
//            bijs = new HashMap<>();
//            newGenPowBijs = new HashMap<>();
//            schnorrZKPbijs = new HashMap<>();
//            pairwiseKeysMAC = new HashMap<>();
//            pairwiseKeysKC = new HashMap<>();
//            hMacsMAC = new HashMap<>();
//            hMacsKC = new HashMap<>();


             gPowAij = new HashMap<>();
             schnorrZKPaij = new HashMap<>();
             bij = new HashMap<>();
             gPowBij = new HashMap<>();
             schnorrZKPbij = new HashMap<>();
             yi = new HashMap<>();
             gPowYi = new HashMap<>();
             gPowZi = new HashMap<>();
             schnorrZKPyi = new HashMap<>();
             signerID = new ArrayList<>();


// ****************************** ROUND 2 ****************************************

             newGen = new HashMap<>();
             bijs = new HashMap<>();
             newGenPowBijs = new HashMap<>();
             schnorrZKPbijs = new HashMap<>();

            // ****************************** ROUND 3 ****************************************
             gPowZiPowYi = new HashMap<>();
            chaumPedersonZKPi = new HashMap<>();
             pairwiseKeysMAC = new HashMap<>();
             pairwiseKeysKC = new HashMap<>();
             hMacsMAC = new HashMap<>();
             hMacsKC = new HashMap<>();
        }



        /**
         * Run the JPAKE+ Protocol server side code. Requires an established
         * connection between the client and server to be set up prior to use.
         *
         * @exception  IOException Catches IOExceptions inside but throws
         *             others.
         */
        public void jPAKEPlusProtocol() throws Exception {
//                                    resetKeys();
            try {
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
                while (roundOneComplete.containsValue(false)) {
                } // busy wait
                System.out.println("************ ROUND 1V **********");
                RoundOneResponse dataRoundOne = setDataRoundOneResponse();
                out.println(gson.toJson(dataRoundOne));

                response = in.readLine();
                if (response.equals("0")) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    roundOneVComplete.replace(id, true);
                }
                System.out.println(roundOneVComplete.toString());
                while (roundOneVComplete.containsValue(false)) {
                }
                // round 2
                System.out.println("************ ROUND 2 ***********");

                out.println("1"); // OK

                // Take in users round two data
                response = in.readLine();
                RoundTwo roundTwo = gson.fromJson(response, RoundTwo.class);
                updateDataRoundTwo(id, roundTwo);
                roundTwoComplete.replace(id, true);
                while (roundTwoComplete.containsValue(false)) {
                }
                System.out.println("*********** ROUND 2V ***********");
                RoundTwoResponse dataRoundTwo = setDataRoundTwoResponse();
                out.println(gson.toJson(dataRoundTwo));

                response = in.readLine();
                if (response.equals("0")) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    roundTwoVComplete.replace(id, true);
                }
                while (roundTwoVComplete.containsValue(false)) {
                }
                System.out.println("************ ROUND 3 ***********");

                out.println("1"); // OK

                response = in.readLine();
                RoundThree roundThree = gson.fromJson(response, RoundThree.class);
                updateDataRoundThree(id, roundThree);
                roundThreeComplete.replace(id, true);
                while (roundThreeComplete.containsValue(false)) {
                }
                System.out.println("************ ROUND 4 ***********");
                RoundThreeResponse dataRoundThree = setDataRoundThreeResponse();
                out.println(gson.toJson(dataRoundThree));

                response = in.readLine();

                if (response.equals(0)) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    roundFourComplete.replace(id, true);
                }
                while (roundFourComplete.containsValue(false)) {
                }
                System.out.println("******* KEY COMPUTATION *******");
                out.println("1");

                response = in.readLine();
                if (response.equals("1")) {
                    System.out.println("Session Keys Computed");
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        public void updateSpekeDataRoundOne(long id, SpekeRoundOne data) {
            gPowYiSpeke.put(id, data.getgPowYi());
            gPowZiSpeke.put(id, data.getgPowZi());
            gsPowXiSpeke.put(id, data.getGsPowXi());
            schnorrZKPiSpeke.put(id, data.getSchnorrZKPi());
            xiSpeke.put(id, data.getXi());
            yiSpeke.put(id, data.getYi());
            signerID.add(data.getSignerID());
        }

        public SpekeRoundOneResponse setSpekeDataRoundOneResponse() {
            SpekeRoundOneResponse r = new SpekeRoundOneResponse();
            r.setgPowYi(gPowYiSpeke);
            r.setgPowZi(gPowZiSpeke);
            r.setGsPowXi(gsPowXiSpeke);
            r.setXi(xiSpeke);
            r.setYi(yiSpeke);
            r.setSchnorrZKPi(schnorrZKPiSpeke);
            r.setSignerID(signerID);
            return r;
        }

        public void updateSpekeDataRoundTwo(long id, SpekeRoundTwo data) {
            chaumPedersonZKPiSpeke.put(id, data.getChaumPedersonZKPi());
            gPowZiPowYiSpeke.put(id, data.getgPowZiPowYi());
            hMacsKCSpeke.put(id, data.gethMacsKC());
            hMacsMACSpeke.put(id, data.gethMacsMAC());
            pairwiseKeysKCSpeke.put(id, data.getPairwiseKeysKC());
            pairwiseKeysMACSpeke.put(id, data.getPairwiseKeysMAC());
        }

        public SpekeRoundTwoResponse setSpekeDataRoundTwoResponse() {
            SpekeRoundTwoResponse r = new SpekeRoundTwoResponse();
            r.setChaumPedersonZKPi(chaumPedersonZKPiSpeke);
            r.setgPowZiPowYi(gPowZiPowYiSpeke);
            r.sethMacsKC(hMacsKCSpeke);
            r.sethMacsMAC(hMacsMACSpeke);
            r.setPairwiseKeysKC(pairwiseKeysKCSpeke);
            r.setPairwiseKeysMAC(pairwiseKeysMACSpeke);
            return r;
        }

        public void sPEKEPlusProtocol() throws  Exception {
            try {
                out.println(":SPEKE");
                RoundZero roundZero = new RoundZero();
                roundZero.setClientIDs(clientIDs);
                out.println(gson.toJson(roundZero));

                // round 1
                response = in.readLine();
                SpekeRoundOne roundOne = gson.fromJson(response, SpekeRoundOne.class);

                updateSpekeDataRoundOne(id, roundOne);
                roundOneComplete.replace(id, true);
                System.out.println(roundOneComplete.toString());
                while (roundOneComplete.containsValue(false)) {
                } // busy wait

                System.out.println("************ ROUND 1V **********");
                SpekeRoundOneResponse dataRoundOne = setSpekeDataRoundOneResponse();
                out.println(gson.toJson(dataRoundOne));

                response = in.readLine();
                if (response.equals("0")) {
                    System.out.println("All clients failed to verify successfully");
                    System.exit(0);
                } else {
                    roundOneVComplete.replace(id, true);
                }
                System.out.println(roundOneVComplete.toString());
                while (roundOneVComplete.containsValue(false)) {
                }

                // round 2
                System.out.println("************ ROUND 2 ***********");

                out.println("1"); // OK

                // Take in users round two data
                response = in.readLine();
                SpekeRoundTwo roundTwo = gson.fromJson(response, SpekeRoundTwo.class);
                System.out.println(roundTwo.getgPowZiPowYi().toString());
                updateSpekeDataRoundTwo(id, roundTwo);
                roundTwoComplete.replace(id, true);
                System.out.println(roundTwoComplete.toString());
                while (roundTwoComplete.containsValue(false)) {
                }
                System.out.println(roundTwoComplete.toString());
                System.out.println("*********** ROUND 2V ***********");
                SpekeRoundTwoResponse dataRoundTwo = setSpekeDataRoundTwoResponse();
                out.println(gson.toJson(dataRoundTwo));

                response = in.readLine();
                if (response.equals("0")) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    roundTwoVComplete.replace(id, true);
                }
                while (roundTwoVComplete.containsValue(false)) {
                }

                System.out.println("******* KEY COMPUTATION *******");
                out.println("1");

                response = in.readLine();
                if (response.equals("1")) {
                    System.out.println("Session Keys Computed");
                }

            }
            catch(IOException e) {
                e.printStackTrace();
            }
        }

        public void updateECDataRoundOne(Long id, ECRoundOne data) {
            aijEC.put(id, data.getAij());
            gPowAijEC.put(id, data.getgPowAij());
            schnorrZKPaijEC.put(id, data.getSchnorrZKPaij());
            bijEC.put(id, data.getBij());
            gPowBijEC.put(id, data.getgPowBij());
            schnorrZKPbijEC.put(id, data.getSchnorrZKPbij());
            yiEC.put(id, data.getYi());
            gPowYiEC.put(id, data.getgPowYi());
            gPowZiEC.put(id, data.getgPowZi());
            schnorrZKPyiEC.put(id, data.getSchnorrZKPyi());
            signerID.add(data.getSignerID());
        }

        public ECRoundOneResponse setECDataRoundOneResponse() {
            ECRoundOneResponse r = new ECRoundOneResponse();
            r.setAij(aijEC);
            r.setgPowAij(gPowAijEC);
            r.setSchnorrZKPaij(schnorrZKPaijEC);
            r.setBij(bijEC);
            r.setgPowBij(gPowBijEC);
            r.setSchnorrZKPbij(schnorrZKPbijEC);
            r.setYi(yiEC);
            r.setgPowYi(gPowYiEC);
            r.setgPowZi(gPowZiEC);
            r.setSchnorrZKPyi(schnorrZKPyiEC);
            r.setSignerID(signerID);
            return r;
        }

        public void updateECDataRoundTwo(Long id, ECRoundTwo data) {
            newGenEC.put(id, data.getNewGen());
            bijsEC.put(id, data.getBijs());
            newGenPowBijsEC.put(id, data.getNewGenPowBijs());
            schnorrZKPbijsEC.put(id, data.getSchnorrZKPbijs());
//            signerIDEC.add(data.getSignerID());
        }

        public ECRoundTwoResponse setECDataRoundTwoResponse() {
            ECRoundTwoResponse r = new ECRoundTwoResponse();
            r.setNewGen(newGenEC);
            r.setBijs(bijsEC);
            r.setNewGenPowBijs(newGenPowBijsEC);
            r.setSchnorrZKPbijs(schnorrZKPbijsEC);
//            r.setSignerID(signerID);
            return r;
        }

        public void updateECDataRoundThree(Long id, ECRoundThree data) {
            gPowZiPowYiEC.put(id, data.getgPowZiPowYi());
            chaumPedersonZKPiEC.put(id, data.getChaumPedersonZKPi());
            pairwiseKeysKCEC.put(id, data.getPairwiseKeysKC());
            pairwiseKeysMACEC.put(id, data.getPairwiseKeysMAC());
            hMacsKCEC.put(id, data.gethMacsKC());
            hMacsMACEC.put(id, data.gethMacsMAC());
        }

        public ECRoundThreeResponse setECDataRoundThreeResponse() {
            ECRoundThreeResponse r = new ECRoundThreeResponse();
            r.setChaumPedersonZKPi(chaumPedersonZKPiEC);
            r.setgPowZiPowYi(gPowZiPowYiEC);
            r.sethMacsKC(hMacsKCEC);
            r.sethMacsMAC(hMacsMACEC);
            r.setPairwiseKeysKC(pairwiseKeysKCEC);
            r.setPairwiseKeysMAC(pairwiseKeysMACEC);
            return r;
        }

        public void jPAKEPlusECProtocol() throws  Exception {
            try {
                out.println(":EC");
                RoundZero roundZero = new RoundZero();
                roundZero.setClientIDs(clientIDs);
                out.println(gson.toJson(roundZero));
                // round 1
                response = in.readLine();
                ECRoundOne roundOne = gson.fromJson(response, ECRoundOne.class);
                System.out.println(roundOne.getSignerID());
                updateECDataRoundOne(id, roundOne);


                roundOneComplete.replace(id, true);
                System.out.println(roundOneComplete.toString());
                while (roundOneComplete.containsValue(false)) {
                } // busy wait
                System.out.println("************ ROUND 1V **********");
                ECRoundOneResponse dataRoundOne = setECDataRoundOneResponse();
                out.println(gson.toJson(dataRoundOne));

                response = in.readLine();
                if (response.equals("0")) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    roundOneVComplete.replace(id, true);
                }
                System.out.println(roundOneVComplete.toString());
                while (roundOneVComplete.containsValue(false)) {
                }
                // round 2
                System.out.println("************ ROUND 2 ***********");

                out.println("1"); // OK

                // Take in users round two data
                response = in.readLine();
                ECRoundTwo roundTwo = gson.fromJson(response, ECRoundTwo.class);
                updateECDataRoundTwo(id, roundTwo);
                roundTwoComplete.replace(id, true);
                while (roundTwoComplete.containsValue(false)) {
                }
                System.out.println("*********** ROUND 2V ***********");
                ECRoundTwoResponse dataRoundTwo = setECDataRoundTwoResponse();
                out.println(gson.toJson(dataRoundTwo));

                response = in.readLine();
                if (response.equals("0")) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    roundTwoVComplete.replace(id, true);
                }
                while (roundTwoVComplete.containsValue(false)) {
                }
                System.out.println("************ ROUND 3 ***********");

                out.println("1"); // OK

                response = in.readLine();
                ECRoundThree roundThree = gson.fromJson(response, ECRoundThree.class);
                updateECDataRoundThree(id, roundThree);
                roundThreeComplete.replace(id, true);
                while (roundThreeComplete.containsValue(false)) {
                }
                System.out.println("************ ROUND 4 ***********");
                ECRoundThreeResponse dataRoundThree = setECDataRoundThreeResponse();
                out.println(gson.toJson(dataRoundThree));

                response = in.readLine();

                if (response.equals(0)) {
                    throw new Exception("All clients failed to verify successfully");
                } else {
                    roundFourComplete.replace(id, true);
                }
                while (roundFourComplete.containsValue(false)) {
                }
                System.out.println("******* KEY COMPUTATION *******");
                out.println("1");

                response = in.readLine();
                if (response.equals("1")) {
                    System.out.println("Session Keys Computed");
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
