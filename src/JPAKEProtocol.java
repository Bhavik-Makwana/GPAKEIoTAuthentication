/*
 * Copyright (c) 1995, 2008, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle or the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.util.Scanner;
import java.util.StringTokenizer;

public class JPAKEProtocol {
    private static final int WAITING = 0;
    private static final int SENTKNOCKKNOCK = 1;
    private static final int SENTCLUE = 2;
    private static final int ANOTHER = 3;

    private static final int SENTPASSWORD = 10;
    private static final int ROUND_1 = 11;
    private static final int VROUND_1 = 12;
    private static final int ROUND_2 = 13;
    private static final int VROUND_2 = 14;
    private static final int ROUND_3 = 15;
    private static final int VROUND_3 = 16;
    private static final int NUMJOKES = 5;

    private int state = WAITING;
    private int currentJoke = 0;

    private String[] clues = { "Turnip", "Little Old Lady", "Atch", "Who", "Who" };
    private String[] answers = { "Turnip the heat, it's cold in here!",
            "I didn't know you could yodel!",
            "Bless you!",
            "Is there an owl in here?",
            "Is there an echo in here?" };

    public int processInput2(String input) {
        StringTokenizer st = new StringTokenizer(input);
        int result;
        int oprnd1 = Integer.parseInt(st.nextToken());
        String operation = st.nextToken();
        int oprnd2 = Integer.parseInt(st.nextToken());

        // perform the required operation.
        if (operation.equals("+"))
        {
            result = oprnd1 + oprnd2;
        }

        else if (operation.equals("-"))
        {
            result = oprnd1 - oprnd2;
        }
        else if (operation.equals("*"))
        {
            result = oprnd1 * oprnd2;
        }
        else
        {
            result = oprnd1 / oprnd2;
        }


        return result;
    }
//    public Object conn(String theInput, int n) {
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
//
//        if (state == WAITING) {
//            theOutput = "Enter the password to join the network";
//            state = SENTPASSWORD;
//        }
//        else if (state == SENTPASSWORD) {
//            // verify
//            state = ROUND_1;
//        }
//        else if (state == ROUND_1) {
//            // round 1
//            for (int i=0; i<n; i++) {
//
//                signerID[i] = i + "";
//
//                // aij in [0, q-1], b_ij in [1, q-1]
//                for (int j=0; j<n; j++) {
//
//                    if (i==j){
//                        continue;
//                    }
//
//                    // aij and ZKP
//                    aij[i][j] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
//                            q.subtract(BigInteger.ONE), new SecureRandom());
//
//                    gPowAij[i][j] = g.modPow(aij[i][j], p);
//
//                    schnorrZKP.generateZKP(p, q, g, gPowAij[i][j], aij[i][j], signerID[i]);
//                    schnorrZKPaij[i][j][0] = schnorrZKP.getGenPowV();
//                    schnorrZKPaij[i][j][1] = schnorrZKP.getR();
//
//                    // bij and ZKP
//                    bij[i][j] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE,
//                            q.subtract(BigInteger.ONE), new SecureRandom());
//
//                    gPowBij[i][j] = g.modPow(bij[i][j], p);
//
//                    schnorrZKP.generateZKP(p, q, g, gPowBij[i][j], bij[i][j], signerID[i]);
//                    schnorrZKPbij[i][j][0] = schnorrZKP.getGenPowV();
//                    schnorrZKPbij[i][j][1] = schnorrZKP.getR();
//                }
//
//                // yi from Zq and ZKP
//                yi[i] = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ZERO,
//                        q.subtract(BigInteger.ONE), new SecureRandom());
//
//                gPowYi[i] = g.modPow(yi[i], p);
//
//                signerID[i] = i + "";
//
//                schnorrZKP.generateZKP(p, q, g, gPowYi[i], yi[i], signerID[i]);
//                schnorrZKPyi[i][0] = schnorrZKP.getGenPowV();
//                schnorrZKPyi[i][1] = schnorrZKP.getR();
//            }
//            state = VROUND_1;
//        }
//        else if (state == VROUND_1) {
//            // round 1
//            state = VROUND_1;
//        }
//        else if (state == ROUND_2) {
//            // round 2
//            state = VROUND_2;
//        }
//        else if (state == VROUND_2) {
//            // verify round 2
//            state = VROUND_2;
//        }
//        else if (state == ROUND_3) {
//            // round 3
//            state = ROUND_3;
//        }
//        else if (state == VROUND_3) {
//            // verify round 3
//            state = WAITING;
//        }
//        return theOutput;
//
//    }
    public String processInput(String theInput) {
        String theOutput = null;

        if (state == WAITING) {
            theOutput = "Knock! Knock!";
            state = SENTKNOCKKNOCK;
        } else if (state == SENTKNOCKKNOCK) {
            if (theInput.equalsIgnoreCase("Who's there?")) {
                theOutput = clues[currentJoke];
                state = SENTCLUE;
            } else {
                theOutput = "You're supposed to say \"Who's there?\"! " +
                        "Try again. Knock! Knock!";
            }
        } else if (state == SENTCLUE) {
            if (theInput.equalsIgnoreCase(clues[currentJoke] + " who?")) {
                theOutput = answers[currentJoke] + " Want another? (y/n)";
                state = ANOTHER;
            } else {
                theOutput = "You're supposed to say \"" +
                        clues[currentJoke] +
                        " who?\"" +
                        "! Try again. Knock! Knock!";
                state = SENTKNOCKKNOCK;
            }
        } else if (state == ANOTHER) {
            if (theInput.equalsIgnoreCase("y")) {
                theOutput = "Knock! Knock!";
                if (currentJoke == (NUMJOKES - 1))
                    currentJoke = 0;
                else
                    currentJoke++;
                state = SENTKNOCKKNOCK;
            } else {
                theOutput = "Bye.";
                state = WAITING;
            }
        }
        return theOutput;
    }
//
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
