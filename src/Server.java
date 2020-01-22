import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.*;

public class Server {
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // don't need to specify a hostname, it will be the current machine
        ServerSocket ss = new ServerSocket(7777);
        System.out.println("ServerSocket awaiting connections...");
        Socket socket = ss.accept(); // blocking call, this will wait until a connection is attempted on this port.
        System.out.println("Connection from " + socket + "!");

        // get the input stream from the connected socket
        InputStream inputStream = socket.getInputStream();
        // create a DataInputStream so we can read data from it.
//        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        Map<Integer, Message> messages = new HashMap<>();
        messages.put(1, new Message("Hello from the other side!"));
        messages.put(2, new Message("How are you doing?"));
        messages.put(3, new Message("What time is it?"));
        messages.put(4, new Message("Hi hi hi hi."));
        objectOutputStream.writeObject(messages);
        // read the list of messages from the socket
//        List<Message> listOfMessages = (List<Message>) objectInputStream.readObject();
//        System.out.println("Received [" + listOfMessages.size() + "] messages from: " + socket);
        // print out the text of every message


        System.out.println("Closing sockets.");
        ss.close();
        socket.close();
    }
}