import java.math.BigInteger;
import java.util.ArrayList;

public class RoundTwo {
    //    BigInteger [][] newGen = new BigInteger [n][n];
    private ArrayList<BigInteger> newGen = new ArrayList<>();
    //    BigInteger [][] bijs = new BigInteger [n][n];
    private ArrayList<BigInteger> bijs = new ArrayList<>();
    //    BigInteger [][] newGenPowBijs = new BigInteger [n][n];
    private ArrayList<BigInteger> newGenPowBijs = new ArrayList<>();;
    //    BigInteger [][][] schnorrZKPbijs = new BigInteger [n][n][2];
    private ArrayList<ArrayList<BigInteger>> schnorrZKPbijs = new ArrayList<>();

    RoundTwo() {};
    public ArrayList<BigInteger> getNewGen() {
        return newGen;
    }

    public void setNewGen(ArrayList<BigInteger> newGen) {
        this.newGen = newGen;
    }

    public ArrayList<BigInteger> getBijs() {
        return bijs;
    }

    public void setBijs(ArrayList<BigInteger> bijs) {
        this.bijs = bijs;
    }

    public ArrayList<BigInteger> getNewGenPowBijs() {
        return newGenPowBijs;
    }

    public void setNewGenPowBijs(ArrayList<BigInteger> newGenPowBijs) {
        this.newGenPowBijs = newGenPowBijs;
    }

    public ArrayList<ArrayList<BigInteger>> getSchnorrZKPbijs() {
        return schnorrZKPbijs;
    }

    public void setSchnorrZKPbijs(ArrayList<ArrayList<BigInteger>> schnorrZKPbijs) {
        this.schnorrZKPbijs = schnorrZKPbijs;
    }
}
