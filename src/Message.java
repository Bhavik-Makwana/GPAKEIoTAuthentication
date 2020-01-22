import java.io.*;


// must implement Serializable in order to be sent
public class Message implements Serializable{
    private final String text;

    public Message(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }
}




// Server output
/*
ServerSocket awaiting connections...
Connection from Socket[addr=/127.0.0.1,port=62360,localport=7777]!
Received [4] messages from: Socket[addr=/127.0.0.1,port=62360,localport=7777]
All messages:
Hello from the other side!
How are you doing?
What time is it?
Hi hi hi hi.
Closing sockets.
*/

// Client output
/*
Connected!
Sending messages to the ServerSocket
Closing socket and terminating program.
*/
