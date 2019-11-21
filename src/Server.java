import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.concurrent.Executors;

/**
 * Written by Martin Ombura Jr. <@martinomburajr>
 */
public class Server {
    public static void main(String[] args) {
        connectToServerMultiple();
    }
    public static void connectToServerMultiple() {
        int max_con = 3; //indicate maximum number of connections.
        int port = 8187;

        //Create multiple ServerSockets to connect to a server
        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException e) {
            e.printStackTrace();
        }
        //Create a for loop that creates max_con number of threads
        for (int i = 0; i < max_con; i++) {
            ServerSocket finalServerSocket = serverSocket;
            //Create the thread
            Runnable runnable = () -> {
                try {
                    Socket listenerSocket = finalServerSocket.accept();
                    InputStream inputToServer = listenerSocket.getInputStream();
                    OutputStream outputFromServer = listenerSocket.getOutputStream();

                    Scanner input = new Scanner(inputToServer, "UTF-8");
                    PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputFromServer, "UTF-8"), true);

                    printWriter.println("Welcome Minion! I'll multiply the number you give by 10.\n Type -19 to quit");
                    printWriter.println("I'm Running on Thread: " + Thread.currentThread().getName());

                    boolean done = false;
                    while(!done && input.hasNextLine()) {
                        String line = input.nextLine();
                        double inputDouble = 0;

                        try{
                            inputDouble = Double.parseDouble(line);
                            //If input is -19 or line == null, terminate and close socket
                            if(line == null || inputDouble == -19) {
                                done = true;
                                printWriter.println("Sad to see you leave! ... Closing Connection!");
                                listenerSocket.close();
                            }
                            printWriter.println("Your answer is: " + inputDouble * 10);
                        }catch (Exception ex) {
                            printWriter.println(":{( - Only insert numbers!!!");
                        }
                    }

                } catch (IOException e) {
                    e.printStackTrace();
                }
            };
            //Execute the runnables!
            Executors.newCachedThreadPool().execute(runnable);
        }
    }
}