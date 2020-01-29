import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

public class RoundTwoResponse {
    //    BigInteger [][] newGen = new BigInteger [n][n];
//    ArrayList<BigInteger> newGen = new ArrayList<>();
    private HashMap<Long, ArrayList<BigInteger>> newGen = new HashMap<>();
    //    BigInteger [][] bijs = new BigInteger [n][n];
//    ArrayList<BigInteger> bijs = new ArrayList<>();
    private HashMap<Long, ArrayList<BigInteger>> bijs = new HashMap<>();
    //    BigInteger [][] newGenPowBijs = new BigInteger [n][n];
//    ArrayList<BigInteger> newGenPowBijs = new ArrayList<>();;
    private HashMap<Long, ArrayList<BigInteger>> newGenPowBijs = new HashMap<>();
    //    BigInteger [][][] schnorrZKPbijs = new BigInteger [n][n][2];
//    ArrayList<ArrayList<BigInteger>> schnorrZKPbijs = new ArrayList<>();
    private HashMap<Long, ArrayList<ArrayList<BigInteger>>> schnorrZKPbijs = new HashMap<>();

    private ArrayList<String> SignerID = new ArrayList<>();

    public HashMap<Long, ArrayList<BigInteger>> getNewGen() {
        return newGen;
    }

    public void setNewGen(HashMap<Long, ArrayList<BigInteger>> newGen) {
        this.newGen = newGen;
    }

    public HashMap<Long, ArrayList<BigInteger>> getBijs() {
        return bijs;
    }

    public void setBijs(HashMap<Long, ArrayList<BigInteger>> bijs) {
        this.bijs = bijs;
    }

    public HashMap<Long, ArrayList<BigInteger>> getNewGenPowBijs() {
        return newGenPowBijs;
    }

    public void setNewGenPowBijs(HashMap<Long, ArrayList<BigInteger>> newGenPowBijs) {
        this.newGenPowBijs = newGenPowBijs;
    }

    public HashMap<Long, ArrayList<ArrayList<BigInteger>>> getSchnorrZKPbijs() {
        return schnorrZKPbijs;
    }

    public void setSchnorrZKPbijs(HashMap<Long, ArrayList<ArrayList<BigInteger>>> schnorrZKPbijs) {
        this.schnorrZKPbijs = schnorrZKPbijs;
    }

    public ArrayList<String> getSignerID() {
        return SignerID;
    }

    public void setSignerID(ArrayList<String> signerID) {
        SignerID = signerID;
    }
}
