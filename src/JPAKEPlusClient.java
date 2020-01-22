import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class JPAKEPlusClient {
    BigInteger p = new BigInteger("C196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16);
    BigInteger q = new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16);
    BigInteger g = new BigInteger("A59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16);
    BigInteger bigTwo = new BigInteger("2", 16);

    public static void main(String[] args) throws IOException, ClassNotFoundException {

        if (args.length != 2) {
            System.err.println(
                    "Usage: java EchoClient <host name> <port number>");
            System.exit(1);
        }

        String hostName = args[0];
        int portNumber = Integer.parseInt(args[1]);

        try (
                Socket jpSocket = new Socket(hostName, portNumber);
                DataInputStream in = new DataInputStream(jpSocket.getInputStream());
                DataOutputStream out = new DataOutputStream(jpSocket.getOutputStream());
                ObjectOutputStream objOut = new ObjectOutputStream(jpSocket.getOutputStream());
                ObjectInputStream objIn = new ObjectInputStream(jpSocket.getInputStream());
                Scanner sc = new Scanner(System.in);

        ) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            String fromServer;
            String fromUser;


                Map<Integer, Socket> c = (HashMap<Integer,Socket>) objIn.readObject();
            for (Map.Entry<Integer, Socket> entry : c.entrySet()) {
                Integer key = entry.getKey();
                Socket value = entry.getValue();
                System.out.println(key +" " + value.getPort());
            }
                System.out.println("Answer ");

        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to " +
                    hostName);
            e.printStackTrace();
            System.exit(1);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static BigInteger getSHA256 (String s)
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

//    public static void round1()
//    {
//        BigInteger [][] aij = new BigInteger [n][n];
//        BigInteger [][] gPowAij = new BigInteger [n][n];
//        BigInteger [][][] schnorrZKPaij = new BigInteger [n][n][2];
//
//        BigInteger [][] bij = new BigInteger [n][n];
//        BigInteger [][] gPowBij = new BigInteger [n][n];
//        BigInteger [][][] schnorrZKPbij = new BigInteger [n][n][2];
//
//        BigInteger [] yi = new BigInteger [n];
//        BigInteger [] gPowYi = new BigInteger [n];
//        BigInteger [] gPowZi = new BigInteger [n];
//        BigInteger [][] schnorrZKPyi = new BigInteger [n][2]; // {g^v, r}
//
//        String [] signerID = new String [n];
//
//        SchnorrZKP schnorrZKP = new SchnorrZKP();
//        String theOutput = null;
//        for (int i=0; i<n; i++) {
//
//            signerID[i] = i + "";
//
//            // aij in [0, q-1], b_ij in [1, q-1]
//            for (int j=0; j<n; j++) {
//
//                if (i==j){
//                    continue;
//                }
//
//                // aij and ZKP
//                aij[i][j] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
//                        q.subtract(BigInteger.ONE), new SecureRandom());
//
//                gPowAij[i][j] = g.modPow(aij[i][j], p);
//
//                schnorrZKP.generateZKP(p, q, g, gPowAij[i][j], aij[i][j], signerID[i]);
//                schnorrZKPaij[i][j][0] = schnorrZKP.getGenPowV();
//                schnorrZKPaij[i][j][1] = schnorrZKP.getR();
//
//                // bij and ZKP
//                bij[i][j] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
//                        q.subtract(BigInteger.ONE), new SecureRandom());
//
//                gPowBij[i][j] = g.modPow(bij[i][j], p);
//
//                schnorrZKP.generateZKP(p, q, g, gPowBij[i][j], bij[i][j], signerID[i]);
//                schnorrZKPbij[i][j][0] = schnorrZKP.getGenPowV();
//                schnorrZKPbij[i][j][1] = schnorrZKP.getR();
//            }
//
//            // yi from Zq and ZKP
//            yi[i] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
//                    q.subtract(BigInteger.ONE), new SecureRandom());
//
//            gPowYi[i] = g.modPow(yi[i], p);
//
//            signerID[i] = i + "";
//
//            schnorrZKP.generateZKP(p, q, g, gPowYi[i], yi[i], signerID[i]);
//            schnorrZKPyi[i][0] = schnorrZKP.getGenPowV();
//            schnorrZKPyi[i][1] = schnorrZKP.getR();
//        }
//    }

//    private class SchnorrZKP {
//
//        private BigInteger genPowV = null;
//        private BigInteger r = null;
//
//        private SchnorrZKP () {
//            // constructor
//        }
//
//        private void generateZKP (BigInteger p, BigInteger q, BigInteger gen,
//                                  BigInteger genPowX, BigInteger x, String signerID){
//
//            /* Generate a random v from [1, q-1], and compute V = gen^v */
//            BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
//                    q.subtract(BigInteger.ONE), new SecureRandom());
//            genPowV = gen.modPow(v,p);
//            BigInteger h = getSHA256(gen,genPowV,genPowX,signerID); // h
//
//            r = v.subtract(x.multiply(h)).mod(q); // r = v-x*h
//        }
//
//        private BigInteger getGenPowV() {
//            return genPowV;
//        }
//
//        private BigInteger getR() {
//            return r;
//        }
//    }

}
