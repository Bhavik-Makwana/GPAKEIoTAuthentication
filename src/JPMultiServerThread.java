/*
 * Copyright (c) 1995, 2013, Oracle and/or its affiliates. All rights reserved.
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

import java.net.*;
import java.io.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.StringTokenizer;

import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class JPMultiServerThread extends Thread {
    private Socket socket = null;

    public JPMultiServerThread(Socket socket) {
        super("JPMultiServerThread");
        this.socket = socket;
    }

    public void run() {

        try (

                DataInputStream in = new DataInputStream(socket.getInputStream());
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                ObjectOutputStream objOut = new ObjectOutputStream(socket.getOutputStream());
//                        new InputStreamReader(
//                                socket.getInputStream()));
            ) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            String inputLine, outputLine;
            JPAKEProtocol jpp = new JPAKEProtocol();
//            outputLine = jpp.processInput(null);
//            out.writeUTF(outputLine);

            while (true) {
//                String input = in.readUTF();
//                if (input.equals("Bye"))
//                    break;
//                System.out.println("Equation received; -" + input);
//                int result;
                Map<Integer, Socket> clients = JPMultiServer.getClients();
//                Map<Integer> clients = new ArrayList<>();
//                clients.add(1);
//                clients.add(2);
                objOut.writeObject(clients);

                // Use StringTokenizer to break the equation into operand and
                // operation
//                result = jpp.processInput2(input);
                System.out.println("Sending the result...");
                // send the result back to the client.
//                out.writeUTF(Integer.toString(result));
            }
//            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
