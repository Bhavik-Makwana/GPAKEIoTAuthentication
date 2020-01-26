
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

    private static HashMap<Long, Boolean> roundComplete = new HashMap<>();
    /**
     * The set of all the print writers for all the clients.  This
     * set is kept so we can easily broadcast messages.
     */
    private static HashSet<PrintWriter> writers = new HashSet<PrintWriter>();


    //    BigInteger [][] aij = new BigInteger [n][n];
//        ArrayList<ArrayList<BigInteger>> aij = new ArrayList<>();
    private static HashMap<Long, ArrayList<BigInteger>> aij = new HashMap<>();
    //    BigInteger [][] gPowAij = new BigInteger [n][n];
//        ArrayList<ArrayList<BigInteger>> gPowAij = new ArrayList<>();
    private static HashMap<Long, ArrayList<BigInteger>> gPowAij = new HashMap<>();
    //    BigInteger [][][] schnorrZKPaij = new BigInteger [n][n][2];
//        ArrayList<ArrayList<ArrayList<BigInteger>>> schnorrZKPaij = new ArrayList<>();
    private static HashMap<Long, ArrayList<ArrayList<BigInteger>>> schnorrZKPaij = new HashMap<>();
    //    BigInteger [][] bij = new BigInteger [n][n];
//        ArrayList<ArrayList<BigInteger>> bij = new ArrayList<>();
    private static HashMap<Long, ArrayList<BigInteger>> bij = new HashMap<>();
    //    BigInteger [][] gPowBij = new BigInteger [n][n];
    private static HashMap<Long, ArrayList<BigInteger>> gPowBij = new HashMap<>();
    //    BigInteger [][][] schnorrZKPbij = new BigInteger [n][n][2];
//        ArrayList<ArrayList<ArrayList<BigInteger>>> schnorrZKPbij = new ArrayList<>();
    private static HashMap<Long, ArrayList<ArrayList<BigInteger>>> schnorrZKPbij = new HashMap<>();
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
    private static HashMap<Long, ArrayList<BigInteger>> newGen = new HashMap<>();
    //    BigInteger [][] bijs = new BigInteger [n][n];
//    ArrayList<BigInteger> bijs = new ArrayList<>();
    private static  HashMap<Long, ArrayList<BigInteger>> bijs = new HashMap<>();
    //    BigInteger [][] newGenPowBijs = new BigInteger [n][n];
//    ArrayList<BigInteger> newGenPowBijs = new ArrayList<>();;
    private static  HashMap<Long, ArrayList<BigInteger>> newGenPowBijs = new HashMap<>();
    //    BigInteger [][][] schnorrZKPbijs = new BigInteger [n][n][2];
//    ArrayList<ArrayList<BigInteger>> schnorrZKPbijs = new ArrayList<>();
    private static  HashMap<Long, ArrayList<ArrayList<BigInteger>>> schnorrZKPbijs = new HashMap<>();





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
                roundComplete.put(id, false);
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
                        out.println(gson.toJson(names));
                        // round 1
                        response = in.readLine();
                        RoundOne roundOne = gson.fromJson(response, RoundOne.class);
                        System.out.println(roundOne.getSignerID());
                        updateDataRoundOne(id, roundOne);
                        roundComplete.replace(id, true);
                        System.out.println(roundComplete.toString());
                        while(roundComplete.containsValue(false)) { } // busy wait
                        // round 1 verification
                        RoundOneResponse dataRoundOne = setDataRoundOneResponse();
                        out.println(gson.toJson(dataRoundOne));
                        roundComplete.replace(id, false);
                        response = in.readLine();
                        if (response.equals("0")) {
                            break;
                        }
                        else {
                            roundComplete.replace(id, true);
                        }
                        while(roundComplete.containsValue(false)) {}
                        // round 2
                        roundComplete.replace(id, false);
                        out.println("1"); // OK

                        // Take in users round two data
                        response = in.readLine();
                        RoundTwo roundTwo = gson.fromJson(response, RoundTwo.class);
                        updateDataRoundTwo(id, roundTwo);
                        roundComplete.replace(id, true);
                        while (roundComplete.containsValue(false)) {}
                        RoundTwoResponse dataRoundTwo = setDataRoundTwoResponse();
                        out.println(gson.toJson(dataRoundTwo));
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
        }

        public RoundTwoResponse setDataRoundTwoResponse() {
            RoundTwoResponse r = new RoundTwoResponse();
            r.setNewGen(newGen);
            r.setBijs(bijs);
            r.setNewGenPowBijs(newGenPowBijs);
            r.setSchnorrZKPbijs(schnorrZKPbijs);
            return r;
        }
    }
}