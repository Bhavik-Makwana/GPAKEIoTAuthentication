import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

public class RoundOneResponse {
    HashMap<Long, ArrayList<BigInteger>> aij;
    HashMap<Long, ArrayList<BigInteger>> gPowAij;
    HashMap<Long, ArrayList<ArrayList<BigInteger>>> schnorrZKPaij;
    HashMap<Long, ArrayList<BigInteger>> bij;
    HashMap<Long, ArrayList<BigInteger>> gPowBij;
    HashMap<Long, ArrayList<ArrayList<BigInteger>>> schnorrZKPbij;
    HashMap<Long, BigInteger> yi;
    HashMap<Long, BigInteger> gPowYi;
    HashMap<Long, BigInteger> gPowZi;
    HashMap<Long, ArrayList<BigInteger>> schnorrZKPyi;
    ArrayList<String> signerID;

    public RoundOneResponse() {}

    public HashMap<Long, ArrayList<BigInteger>> getAij() {
        return aij;
    }

    public void setAij(HashMap<Long, ArrayList<BigInteger>> aij) {
        this.aij = aij;
    }

    public HashMap<Long, ArrayList<BigInteger>> getgPowAij() {
        return gPowAij;
    }

    public void setgPowAij(HashMap<Long, ArrayList<BigInteger>> gPowAij) {
        this.gPowAij = gPowAij;
    }

    public HashMap<Long, ArrayList<ArrayList<BigInteger>>> getSchnorrZKPaij() {
        return schnorrZKPaij;
    }

    public void setSchnorrZKPaij(HashMap<Long, ArrayList<ArrayList<BigInteger>>> schnorrZKPaij) {
        this.schnorrZKPaij = schnorrZKPaij;
    }

    public HashMap<Long, ArrayList<BigInteger>> getBij() {
        return bij;
    }

    public void setBij(HashMap<Long, ArrayList<BigInteger>> bij) {
        this.bij = bij;
    }

    public HashMap<Long, ArrayList<BigInteger>> getgPowBij() {
        return gPowBij;
    }

    public void setgPowBij(HashMap<Long, ArrayList<BigInteger>> gPowBij) {
        this.gPowBij = gPowBij;
    }

    public HashMap<Long, ArrayList<ArrayList<BigInteger>>> getSchnorrZKPbij() {
        return schnorrZKPbij;
    }

    public void setSchnorrZKPbij(HashMap<Long, ArrayList<ArrayList<BigInteger>>> schnorrZKPbij) {
        this.schnorrZKPbij = schnorrZKPbij;
    }

    public HashMap<Long, BigInteger> getYi() {
        return yi;
    }

    public void setYi(HashMap<Long, BigInteger> yi) {
        this.yi = yi;
    }

    public HashMap<Long, BigInteger> getgPowYi() {
        return gPowYi;
    }

    public void setgPowYi(HashMap<Long, BigInteger> gPowYi) {
        this.gPowYi = gPowYi;
    }

    public HashMap<Long, BigInteger> getgPowZi() {
        return gPowZi;
    }

    public void setgPowZi(HashMap<Long, BigInteger> gPowZi) {
        this.gPowZi = gPowZi;
    }

    public HashMap<Long, ArrayList<BigInteger>> getSchnorrZKPyi() {
        return schnorrZKPyi;
    }

    public void setSchnorrZKPyi(HashMap<Long, ArrayList<BigInteger>> schnorrZKPyi) {
        this.schnorrZKPyi = schnorrZKPyi;
    }

    public ArrayList<String> getSignerID() {
        return signerID;
    }

    public void setSignerID(ArrayList<String> signerID) {
        this.signerID = signerID;
    }
}
