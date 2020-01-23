import java.math.BigInteger;
import java.util.ArrayList;

public class RoundOne {
    private ArrayList<BigInteger> aij;
    //    BigInteger [][] gPowAij = new BigInteger [n][n];
    private ArrayList<BigInteger> gPowAij;
    //    BigInteger [][][] schnorrZKPaij = new BigInteger [n][n][2];
    private ArrayList<ArrayList<BigInteger>> schnorrZKPaij;
    //    BigInteger [][] bij = new BigInteger [n][n];
    private ArrayList<BigInteger> bij;
    //    BigInteger [][] gPowBij = new BigInteger [n][n];
    private ArrayList<BigInteger> gPowBij;
    //    BigInteger [][][] schnorrZKPbij = new BigInteger [n][n][2];
    private ArrayList<ArrayList<BigInteger>> schnorrZKPbij;
    //    BigInteger [] yi = new BigInteger [n];
    private BigInteger yi;
    //    BigInteger [] gPowYi = new BigInteger [n];
    private BigInteger gPowYi;
    //    BigInteger [] gPowZi = new BigInteger [n];
    private BigInteger gPowZi;
    //    BigInteger [][] schnorrZKPyi = new BigInteger [n][2]; // {g^v, r}
    private ArrayList<BigInteger> schnorrZKPyi;
    //    String [] signerID = new String [n];
    private String signerID;


    public RoundOne() {
    }
    public ArrayList<BigInteger> getAij() {
        return aij;
    }

    public void setAij(ArrayList<BigInteger> aij) {
        this.aij = aij;
    }

    public ArrayList<BigInteger> getgPowAij() {
        return gPowAij;
    }

    public void setgPowAij(ArrayList<BigInteger> gPowAij) {
        this.gPowAij = gPowAij;
    }

    public ArrayList<ArrayList<BigInteger>> getSchnorrZKPaij() {
        return schnorrZKPaij;
    }

    public void setSchnorrZKPaij(ArrayList<ArrayList<BigInteger>> schnorrZKPaij) {
        this.schnorrZKPaij = schnorrZKPaij;
    }

    public ArrayList<BigInteger> getBij() {
        return bij;
    }

    public void setBij(ArrayList<BigInteger> bij) {
        this.bij = bij;
    }

    public ArrayList<BigInteger> getgPowBij() {
        return gPowBij;
    }

    public void setgPowBij(ArrayList<BigInteger> gPowBij) {
        this.gPowBij = gPowBij;
    }

    public ArrayList<ArrayList<BigInteger>> getSchnorrZKPbij() {
        return schnorrZKPbij;
    }

    public void setSchnorrZKPbij(ArrayList<ArrayList<BigInteger>> schnorrZKPbij) {
        this.schnorrZKPbij = schnorrZKPbij;
    }

    public BigInteger getYi() {
        return yi;
    }

    public void setYi(BigInteger yi) {
        this.yi = yi;
    }

    public BigInteger getgPowYi() {
        return gPowYi;
    }

    public void setgPowYi(BigInteger gPowYi) {
        this.gPowYi = gPowYi;
    }

    public BigInteger getgPowZi() {
        return gPowZi;
    }

    public void setgPowZi(BigInteger gPowZi) {
        this.gPowZi = gPowZi;
    }

    public ArrayList<BigInteger> getSchnorrZKPyi() {
        return schnorrZKPyi;
    }

    public void setSchnorrZKPyi(ArrayList<BigInteger> schnorrZKPyi) {
        this.schnorrZKPyi = schnorrZKPyi;
    }

    public String getSignerID() {
        return signerID;
    }

    public void setSignerID(String signerID) {
        this.signerID = signerID;
    }
}
