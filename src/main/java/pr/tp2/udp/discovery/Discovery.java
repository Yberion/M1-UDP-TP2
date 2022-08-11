package pr.tp2.udp.discovery;

import org.tinylog.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.nio.charset.StandardCharsets;

public class Discovery {
    private static final String IP = "225.0.4.1";
    private static final int PORT = 9999;

    public static void sendWhois(String id) throws IOException {
        // Envoie un message Whois

        InetAddress groupeIP = InetAddress.getByName(IP);

        byte[] contenuMessage = (("WHOIS:" + id).getBytes());

        DatagramPacket message;

        message = new DatagramPacket(contenuMessage, contenuMessage.length, groupeIP, PORT);

        try (MulticastSocket socketEmission = new MulticastSocket(PORT)) {
            Logger.info("From sendWhois - Sending message : " + new String(contenuMessage));

            socketEmission.send(message);
        }
    }

    public static void sendLeaving(String id) throws IOException {
        // Envoie un message Leaving

        InetAddress groupeIP = InetAddress.getByName(IP);

        byte[] contenuMessage = (("LEAVING:" + id).getBytes());

        DatagramPacket message;

        message = new DatagramPacket(contenuMessage, contenuMessage.length, groupeIP, PORT);

        try (MulticastSocket socketEmission = new MulticastSocket(PORT)) {
            Logger.info("From sendLeaving - Sending message : " + new String(contenuMessage));

            socketEmission.send(message);
        }
    }

    public static void sendIAM(String id, String url) throws IOException {
        // Envoie un message IAM

        InetAddress groupeIP = InetAddress.getByName(IP);

        byte[] contenuMessage = (("IAM:" + id + ":" + url).getBytes());

        DatagramPacket message;

        message = new DatagramPacket(contenuMessage, contenuMessage.length, groupeIP, PORT);

        try (MulticastSocket socketEmission = new MulticastSocket(PORT)) {
            Logger.info("From sendIAM - Sending message : " + new String(contenuMessage));

            socketEmission.send(message);
        }
    }

    public static void listenAndReply() throws IOException {
        // Ecoute et affiche les évennements IAM, LEAVING, WHOIS

        final String ID = "051005022";
        final String URL = "https://istic.univ-rennes1.fr/";

        InetAddress groupeIP = InetAddress.getByName(IP);

        DatagramPacket message;
        byte[] contenuMessage;

        String messageReceive;

        try (MulticastSocket socketReception = new MulticastSocket(PORT)) {
            socketReception.joinGroup(groupeIP);

            while (socketReception.isBound()) {
                contenuMessage = new byte[1024];

                message = new DatagramPacket(contenuMessage, contenuMessage.length);

                socketReception.receive(message);

                messageReceive = new String(contenuMessage, 0, message.getLength(), StandardCharsets.US_ASCII);

                Logger.info("From listenAndReply - Receiving message : " + messageReceive);

                String[] splittedMessage = messageReceive.split(":");

                // Make sure we have a message and an id
                // Réponds aux WHOIS si ID = ID
                if (splittedMessage.length >= 2) {
                    if (splittedMessage[0].equals("WHOIS") && splittedMessage[1].equals(ID)) {
                        sendIAM(ID, URL);
                    }
                }
            }
        }
    }

    public static void main(String[] args) throws IOException {
        String cmd = args[0];
        String url = null;
        String id = null;

        if (args.length > 1) {
            id = args[1];
        }

        if (args.length == 3) {
            url = args[2];
        }

        switch (cmd) {
            case "listen":
                listenAndReply();
                break;
            case "iam":
                sendIAM(id, url);
                break;
            case "leaving":
                sendLeaving(id);
                break;
            case "whois":
                sendWhois(id);
                break;
            default:
                Logger.info("Erreur de commande");
                break;
        }
    }
}
