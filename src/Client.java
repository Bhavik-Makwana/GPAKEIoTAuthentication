
import java.io.*;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.*;
public class Client {

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        // need host and port, we want to connect to the ServerSocket at port 7777
        Socket socket = new Socket("localhost", 7777);
        System.out.println("Connected!");

        // get the streams from the socket.
        OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream();
        // create an object output stream from the output stream so we can send an object through it
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

        Map<Integer, Message> listOfMessages  = (HashMap<Integer, Message>) objectInputStream.readObject();
        System.out.println("All messages:");
        for (Map.Entry<Integer, Message> entry : listOfMessages.entrySet()) {
            Integer key = entry.getKey();
            Message value = entry.getValue();
            System.out.println((key +" " + value.getText()));
        }
        System.out.println("Closing socket and terminating program.");
        socket.close();
    }
}