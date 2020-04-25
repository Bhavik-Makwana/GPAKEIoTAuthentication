import JPAKEPlus.POJOs.JPAKEPlusNetwork;
import JPAKEPlus.POJOs.POJOs.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.jupiter.api.Test;
import org.junit.*;
import org.bouncycastle.*;

import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

class JPAKEPlusTest {

    // ****************************** ROUND 1 ****************************************
//    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> aij = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> gPowAij = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, ArrayList<BigInteger>>> schnorrZKPaij = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> bij = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> gPowBij = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, ArrayList<BigInteger>>> schnorrZKPbij = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, BigInteger> yi = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, BigInteger> gPowYi = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, BigInteger> gPowZi = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ArrayList<BigInteger>> schnorrZKPyi = new ConcurrentHashMap<>();
    private static ArrayList<String> signerID = new ArrayList<>();


    // ****************************** ROUND 2 ****************************************

    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> newGen = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> bijs = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> newGenPowBijs = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, ArrayList<BigInteger>>> schnorrZKPbijs = new ConcurrentHashMap<>();

    // ****************************** ROUND 3 ****************************************
    private static ConcurrentHashMap<Long, BigInteger> gPowZiPowYi = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ArrayList<BigInteger>> chaumPedersonZKPi = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> pairwiseKeysMAC = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> pairwiseKeysKC = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> hMacsMAC = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<Long, ConcurrentHashMap<Long, BigInteger>> hMacsKC = new ConcurrentHashMap<>();

    BigInteger p = new BigInteger("C196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16);
    BigInteger q = new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16);
    BigInteger g = new BigInteger("A59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16);
    @Test
    void roundOneSuccess() {
        ArrayList<Long> clients = new ArrayList<>();
        clients.add(0l);
        clients.add(1l);
        clients.add(2l);
        JPAKEPlusNetwork jpake1 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(0l), clients , 0);
        RoundOne roundOne1 = jpake1.roundOne();

        JPAKEPlusNetwork jpake2 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(1l), clients , 1);
        RoundOne roundOne2 = jpake2.roundOne();

        JPAKEPlusNetwork jpake3 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(2l), clients , 2);
        RoundOne roundOne3 = jpake3.roundOne();
    }

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none();
    @Test
    void roundOneVerificationSuccess() {
        exit.expectSystemExitWithStatus(0);
        ArrayList<Long> clients = new ArrayList<>();
        clients.add(0l);
        clients.add(1l);
        clients.add(2l);
        JPAKEPlusNetwork jpake1 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(0l), clients , 0);
        RoundOne roundOne1 = jpake1.roundOne();

        JPAKEPlusNetwork jpake2 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(1l), clients , 1);
        RoundOne roundOne2 = jpake2.roundOne();

        JPAKEPlusNetwork jpake3 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(2l), clients , 2);
        RoundOne roundOne3 = jpake3.roundOne();

        updateDataRoundOne(0l, roundOne1);
        updateDataRoundOne(1l, roundOne2);
        updateDataRoundOne(2l, roundOne3);
        RoundOneResponse roundOneResponse = setDataRoundOneResponse();

        boolean r12 = jpake1.verifyRoundOne(roundOneResponse);
        boolean r11 = jpake2.verifyRoundOne(roundOneResponse);
        boolean r13 = jpake3.verifyRoundOne(roundOneResponse);
        assert r12 == true && r11 == true && r13 == true;
    }

    @Test
    void roundTwoSuccess() {
        exit.expectSystemExitWithStatus(0);
        ArrayList<Long> clients = new ArrayList<>();
        clients.add(0l);
        clients.add(1l);
        clients.add(2l);
        JPAKEPlusNetwork jpake1 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(0l), clients , 0);
        RoundOne roundOne1 = jpake1.roundOne();

        JPAKEPlusNetwork jpake2 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(1l), clients , 1);
        RoundOne roundOne2 = jpake2.roundOne();

        JPAKEPlusNetwork jpake3 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(2l), clients , 2);
        RoundOne roundOne3 = jpake3.roundOne();

        updateDataRoundOne(0l, roundOne1);
        updateDataRoundOne(1l, roundOne2);
        updateDataRoundOne(2l, roundOne3);
        RoundOneResponse roundOneResponse = setDataRoundOneResponse();

        boolean r12 = jpake1.verifyRoundOne(roundOneResponse);
        boolean r11 = jpake2.verifyRoundOne(roundOneResponse);
        boolean r13 = jpake3.verifyRoundOne(roundOneResponse);
        if (r12 == true && r11 == true && r13 == true) {
            jpake1.roundTwo(roundOneResponse);
            jpake2.roundTwo(roundOneResponse);
            jpake3.roundTwo(roundOneResponse);
        }
    }

    @Test
    void verifyRoundTwoSuccess() {
        exit.expectSystemExitWithStatus(0);
        ArrayList<Long> clients = new ArrayList<>();
        clients.add(0l);
        clients.add(1l);
        clients.add(2l);
        JPAKEPlusNetwork jpake1 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(0l), clients , 0);
        RoundOne roundOne1 = jpake1.roundOne();

        JPAKEPlusNetwork jpake2 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(1l), clients , 1);
        RoundOne roundOne2 = jpake2.roundOne();

        JPAKEPlusNetwork jpake3 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(2l), clients , 2);
        RoundOne roundOne3 = jpake3.roundOne();

        updateDataRoundOne(0l, roundOne1);
        updateDataRoundOne(1l, roundOne2);
        updateDataRoundOne(2l, roundOne3);
        RoundOneResponse roundOneResponse = setDataRoundOneResponse();

        boolean r12 = jpake1.verifyRoundOne(roundOneResponse);
        boolean r11 = jpake2.verifyRoundOne(roundOneResponse);
        boolean r13 = jpake3.verifyRoundOne(roundOneResponse);
        if (r12 == true && r11 == true && r13 == true) {
            RoundTwo roundTwo1 = jpake1.roundTwo(roundOneResponse);
            RoundTwo roundTwo2= jpake2.roundTwo(roundOneResponse);
            RoundTwo roundTwo3 = jpake3.roundTwo(roundOneResponse);

            updateDataRoundTwo(0l, roundTwo1);
            updateDataRoundTwo(1l, roundTwo2);
            updateDataRoundTwo(2l, roundTwo3);
            RoundTwoResponse roundTwoResponse = setDataRoundTwoResponse();

            r12 = jpake1.verifyRoundTwo(roundTwoResponse);
            r11 = jpake2.verifyRoundTwo(roundTwoResponse);
            r13 = jpake3.verifyRoundTwo(roundTwoResponse);
            assert (r12 == true && r11 == true && r13 == true);
        }
    }

    @Test
    void roundThreeSuccess() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        exit.expectSystemExitWithStatus(0);
        ArrayList<Long> clients = new ArrayList<>();
        clients.add(0l);
        clients.add(1l);
        clients.add(2l);
        JPAKEPlusNetwork jpake1 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(0l), clients , 0);
        RoundOne roundOne1 = jpake1.roundOne();

        JPAKEPlusNetwork jpake2 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(1l), clients , 1);
        RoundOne roundOne2 = jpake2.roundOne();

        JPAKEPlusNetwork jpake3 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(2l), clients , 2);
        RoundOne roundOne3 = jpake3.roundOne();

        updateDataRoundOne(0l, roundOne1);
        updateDataRoundOne(1l, roundOne2);
        updateDataRoundOne(2l, roundOne3);
        RoundOneResponse roundOneResponse = setDataRoundOneResponse();

        boolean r12 = jpake1.verifyRoundOne(roundOneResponse);
        boolean r11 = jpake2.verifyRoundOne(roundOneResponse);
        boolean r13 = jpake3.verifyRoundOne(roundOneResponse);
        if (r12 == true && r11 == true && r13 == true) {
            RoundTwo roundTwo1 = jpake1.roundTwo(roundOneResponse);
            RoundTwo roundTwo2= jpake2.roundTwo(roundOneResponse);
            RoundTwo roundTwo3 = jpake3.roundTwo(roundOneResponse);

            updateDataRoundTwo(0l, roundTwo1);
            updateDataRoundTwo(1l, roundTwo2);
            updateDataRoundTwo(2l, roundTwo3);
            RoundTwoResponse roundTwoResponse = setDataRoundTwoResponse();

            r12 = jpake1.verifyRoundTwo(roundTwoResponse);
            r11 = jpake2.verifyRoundTwo(roundTwoResponse);
            r13 = jpake3.verifyRoundTwo(roundTwoResponse);
            if (r12 == true && r11 == true && r13 == true) {
                RoundThree roundThree1 = jpake1.roundThree(roundOneResponse, roundTwoResponse);
                RoundThree roundThree2 = jpake2.roundThree(roundOneResponse, roundTwoResponse);
                RoundThree roundThree3 = jpake3.roundThree(roundOneResponse, roundTwoResponse);
            }
        }
    }

    @Test
    void verifyRoundThreeSuccess() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        exit.expectSystemExitWithStatus(0);
        ArrayList<Long> clients = new ArrayList<>();
        clients.add(0l);
        clients.add(1l);
        clients.add(2l);
        JPAKEPlusNetwork jpake1 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(0l), clients , 0);
        RoundOne roundOne1 = jpake1.roundOne();

        JPAKEPlusNetwork jpake2 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(1l), clients , 1);
        RoundOne roundOne2 = jpake2.roundOne();

        JPAKEPlusNetwork jpake3 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(2l), clients , 2);
        RoundOne roundOne3 = jpake3.roundOne();

        updateDataRoundOne(0l, roundOne1);
        updateDataRoundOne(1l, roundOne2);
        updateDataRoundOne(2l, roundOne3);
        RoundOneResponse roundOneResponse = setDataRoundOneResponse();

        boolean r12 = jpake1.verifyRoundOne(roundOneResponse);
        boolean r11 = jpake2.verifyRoundOne(roundOneResponse);
        boolean r13 = jpake3.verifyRoundOne(roundOneResponse);
        if (r12 == true && r11 == true && r13 == true) {
            RoundTwo roundTwo1 = jpake1.roundTwo(roundOneResponse);
            RoundTwo roundTwo2= jpake2.roundTwo(roundOneResponse);
            RoundTwo roundTwo3 = jpake3.roundTwo(roundOneResponse);

            updateDataRoundTwo(0l, roundTwo1);
            updateDataRoundTwo(1l, roundTwo2);
            updateDataRoundTwo(2l, roundTwo3);
            RoundTwoResponse roundTwoResponse = setDataRoundTwoResponse();

            r12 = jpake1.verifyRoundTwo(roundTwoResponse);
            r11 = jpake2.verifyRoundTwo(roundTwoResponse);
            r13 = jpake3.verifyRoundTwo(roundTwoResponse);
            if (r12 == true && r11 == true && r13 == true) {
                RoundThree roundThree1 = jpake1.roundThree(roundOneResponse, roundTwoResponse);
                RoundThree roundThree2 = jpake2.roundThree(roundOneResponse, roundTwoResponse);
                RoundThree roundThree3 = jpake3.roundThree(roundOneResponse, roundTwoResponse);

                updateDataRoundThree(0l, roundThree1);
                updateDataRoundThree(1l, roundThree2);
                updateDataRoundThree(2l, roundThree3);
                RoundThreeResponse roundThreeResponse = setDataRoundThreeResponse();

                r12 = jpake1.roundFour(roundOneResponse, roundTwoResponse, roundThreeResponse);
                r11 = jpake2.roundFour(roundOneResponse, roundTwoResponse, roundThreeResponse);
                r13 = jpake3.roundFour(roundOneResponse, roundTwoResponse, roundThreeResponse);
                assert (r12 == true && r11 == true && r13 == true);

            }
        }
    }


    @Test
    void verifyGroupKeysCreatedSuccessfully() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        exit.expectSystemExitWithStatus(0);
        ArrayList<Long> clients = new ArrayList<>();
        clients.add(0l);
        clients.add(1l);
        clients.add(2l);
        JPAKEPlusNetwork jpake1 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(0l), clients , 0);
        RoundOne roundOne1 = jpake1.roundOne();

        JPAKEPlusNetwork jpake2 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(1l), clients , 1);
        RoundOne roundOne2 = jpake2.roundOne();

        JPAKEPlusNetwork jpake3 = new JPAKEPlusNetwork("deadbeef", p, q, g, 3, Long.toString(2l), clients , 2);
        RoundOne roundOne3 = jpake3.roundOne();

        updateDataRoundOne(0l, roundOne1);
        updateDataRoundOne(1l, roundOne2);
        updateDataRoundOne(2l, roundOne3);
        RoundOneResponse roundOneResponse = setDataRoundOneResponse();

        boolean r12 = jpake1.verifyRoundOne(roundOneResponse);
        boolean r11 = jpake2.verifyRoundOne(roundOneResponse);
        boolean r13 = jpake3.verifyRoundOne(roundOneResponse);
        if (r12 == true && r11 == true && r13 == true) {
            RoundTwo roundTwo1 = jpake1.roundTwo(roundOneResponse);
            RoundTwo roundTwo2= jpake2.roundTwo(roundOneResponse);
            RoundTwo roundTwo3 = jpake3.roundTwo(roundOneResponse);

            updateDataRoundTwo(0l, roundTwo1);
            updateDataRoundTwo(1l, roundTwo2);
            updateDataRoundTwo(2l, roundTwo3);
            RoundTwoResponse roundTwoResponse = setDataRoundTwoResponse();

            r12 = jpake1.verifyRoundTwo(roundTwoResponse);
            r11 = jpake2.verifyRoundTwo(roundTwoResponse);
            r13 = jpake3.verifyRoundTwo(roundTwoResponse);
            if (r12 == true && r11 == true && r13 == true) {
                RoundThree roundThree1 = jpake1.roundThree(roundOneResponse, roundTwoResponse);
                RoundThree roundThree2 = jpake2.roundThree(roundOneResponse, roundTwoResponse);
                RoundThree roundThree3 = jpake3.roundThree(roundOneResponse, roundTwoResponse);

                updateDataRoundThree(0l, roundThree1);
                updateDataRoundThree(1l, roundThree2);
                updateDataRoundThree(2l, roundThree3);
                RoundThreeResponse roundThreeResponse = setDataRoundThreeResponse();

                r12 = jpake1.roundFour(roundOneResponse, roundTwoResponse, roundThreeResponse);
                r11 = jpake2.roundFour(roundOneResponse, roundTwoResponse, roundThreeResponse);
                r13 = jpake3.roundFour(roundOneResponse, roundTwoResponse, roundThreeResponse);
                if (r12 == true && r11 == true && r13 == true) {
                    BigInteger key1 = jpake1.computeKey(roundOneResponse, roundThreeResponse);
                    BigInteger key2 = jpake2.computeKey(roundOneResponse, roundThreeResponse);
                    BigInteger key3 = jpake3.computeKey(roundOneResponse, roundThreeResponse);
                    System.out.println(key1);
                    System.out.println(key2);
                    System.out.println(key3);
                    assert (key1.equals(key2) && key2.equals(key3));

                }

            }
        }
    }












    @Test
    void roundOneVerificationExitWithStatus0() {
        exit.expectSystemExitWithStatus(0);
        ArrayList<Long> clients = new ArrayList<>();
        clients.add(0l);
        clients.add(1l);
        JPAKEPlusNetwork jpake1 = new JPAKEPlusNetwork("deadbeef", p, q, g, 2, Long.toString(0l), clients , 0);
        RoundOne roundOne1 = jpake1.roundOne();

        JPAKEPlusNetwork jpake2 = new JPAKEPlusNetwork("deadbeef", p, q, g, 2, Long.toString(1l), clients , 1);
        RoundOne roundOne2 = jpake2.roundOne();

        updateDataRoundOne(0l, roundOne1);
        updateDataRoundOne(1l, roundOne2);
        RoundOneResponse roundOneResponse = setDataRoundOneResponse();

        jpake1.verifyRoundOne(roundOneResponse);
        jpake2.verifyRoundOne(roundOneResponse);
    }



    public void updateDataRoundOne(Long id, RoundOne data) {

//            aij.put(id, data.getAij());
        gPowAij.put(id, data.getgPowAij());
        schnorrZKPaij.put(id, data.getSchnorrZKPaij());
        bij.put(id, data.getBij());
        gPowBij.put(id, data.getgPowBij());
        schnorrZKPbij.put(id, data.getSchnorrZKPbij());
        yi.put(id, data.getYi());
        gPowYi.put(id, data.getgPowYi());
//            gPowZi.put(id, data.getgPowZi());
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
}