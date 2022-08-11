package pr.tp2.udp.tftp;

import org.tinylog.Logger;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.IntStream;

public class TftpPutServeur {
    private static final int PORT = 6969;
    private static final int PACKET_SIZE = 516;

    public static void main(String[] args) throws IOException {
        // Attends sur le port 6969
        try (DatagramSocket serverSocket = new DatagramSocket(PORT)) {
            // Boucle
            while (serverSocket.isBound()) {
                byte[] buffer = new byte[PACKET_SIZE];

                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

                Logger.info("=========================================================");
                Logger.info("Waiting TFTP packet...");

                // Blockant
                serverSocket.receive(packet);

                // Affichage du packet
                Logger.info("Printing packet:");

                printBuffer(Arrays.copyOfRange(buffer, 0, packet.getLength()));

                // Décodage du packet
                decodeRequest(packet, serverSocket);
                Logger.info("=========================================================");
            }
        }
    }

    public static void sendAck(DatagramSocket serverSocket, short seqNumber, SocketAddress destinationAddr) throws IOException {
        Logger.info("Sending " + seqNumber + " to " + destinationAddr);

        // Construction of the packet
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.putShort((short) 4);
        byteBuffer.putShort(seqNumber);

        byte[] ackBuffer = byteBuffer.array();

        DatagramPacket ackPacket = new DatagramPacket(ackBuffer, ackBuffer.length, destinationAddr);

        // Display done in decode()

        // Send the packet to the destination
        serverSocket.send(ackPacket);
    }

    public static void printBuffer(byte[] bytes) {
        StringBuilder out = new StringBuilder();

        IntStream.range(0, bytes.length).forEach(i ->
        {
            if (i % 16 == 0) {
                out.append("\n");
            }

            out.append(String.format("%02x ", bytes[i]));
        });

        Logger.info(out + "\n");
    }

    public static void decodeRequest(DatagramPacket packet, DatagramSocket serverSocket) throws IOException {
        byte[] packetData = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
        String type = "";

        // Used to decode byte arrays
        Charset charset = StandardCharsets.US_ASCII;

        // Opcode is the first 2 bytes
        byte[] opcodeBytes = Arrays.copyOfRange(packetData, 0, 2);

        ByteBuffer opcodeWrapped = ByteBuffer.wrap(opcodeBytes);

        short opcode = opcodeWrapped.getShort();

        // Opcode (2 bytes)
        switch (opcode) {
            case 1:
            case 2: {
                if (opcode == 1) {
                    // GET
                    type = "1 - Read request (RRQ)";
                } else {
                    // PUT
                    type = "2 - Write request (WRQ)";
                }

                // The first 2 bytes are for Opcode
                int i = 2;

                // Get the position of the 0 delimiter between filename and mode
                while (packetData[i] != 0) {
                    ++i;
                }

                // From 2 to the position of the delimiter (excluded)
                byte[] fileNameBytes = Arrays.copyOfRange(packetData, 2, i);

                String fileName = new String(fileNameBytes, charset);

                // From i + 1 (so we exclude the delimiter) to the position of the last delimiter (excluded)
                byte[] modeBytes = Arrays.copyOfRange(packetData, i + 1, packetData.length - 1);

                String mode = new String(modeBytes, charset);

                Logger.info("Type : " + type + ", fichier : " + fileName + ", mode : " + mode);

                if (opcode == 2) {
                    sendAck(serverSocket, (short) 0, packet.getSocketAddress());
                }

                return;
            }
            case 3: {
                type = "3 - Data (DATA)";

                // block Id is 2 bytes, so from 2 to 4 (excluded)
                byte[] blockIdBytes = Arrays.copyOfRange(packetData, 2, 4);

                ByteBuffer wrapped = ByteBuffer.wrap(blockIdBytes);

                short blockId = wrapped.getShort();

                // the data starts at byte 5 (position 4) to the end
                byte[] dataBytes = Arrays.copyOfRange(packetData, 4, packetData.length);

                Logger.info("Type : " + type + ", block ID : " + blockId + ", block size : " + dataBytes.length);

                Logger.info("Printing DATA:");

                printBuffer(dataBytes);

                sendAck(serverSocket, blockId, packet.getSocketAddress());

                return;
            }
            case 4: {
                type = "4 - Acknowledgment (ACK)";

                // block Id is 2 bytes, so from 2 to 4 (excluded), we want the byte 2 and 3
                byte[] blockIdBytes = Arrays.copyOfRange(packetData, 2, 4);

                ByteBuffer wrapped = ByteBuffer.wrap(blockIdBytes);

                short blockId = wrapped.getShort();

                Logger.info("Type : " + type + ", block ID : " + blockId);

                return;
            }
            case 5: {
                type = "5 - Error (ERROR)";

                // Opcode is the first 2 bytes
                byte[] errorCodeBytes = Arrays.copyOfRange(packetData, 2, 4);

                ByteBuffer errorCodeWrapped = ByteBuffer.wrap(errorCodeBytes);

                short errorCode = errorCodeWrapped.getShort();

                String errorCodeMessage = "";

                switch (errorCode) {
                    case 0:
                        errorCodeMessage = "0 - Not defined, see error message (if any).";
                        break;
                    case 1:
                        errorCodeMessage = "1 - File not found.";
                        break;
                    case 2:
                        errorCodeMessage = "2 - Access violation.";
                        break;
                    case 3:
                        errorCodeMessage = "3 - Disk full or allocation exceeded.";
                        break;
                    case 4:
                        errorCodeMessage = "4 - Illegal TFTP operation.";
                        break;
                    case 5:
                        errorCodeMessage = "5 - Unknown transfer ID.";
                        break;
                    case 6:
                        errorCodeMessage = "6 - File already exists.";
                        break;
                    case 7:
                        errorCodeMessage = "7 - No such user.";
                        break;
                    default:
                        errorCodeMessage = "Unknown error code";
                }

                // From 4 to the end (-1 cause we don't want the 0 delimiter)
                byte[] errorMessageBytes = Arrays.copyOfRange(packetData, 4, packetData.length - 1);

                String errorMessage = new String(errorMessageBytes, charset);

                Logger.info("Type : " + type + ", code erreur : " + errorCodeMessage + ", code message : " + errorMessage);

                return;
            }
            default:
                type = "Unknown Opcode";

                Logger.info("Type : " + type);
        }
    }
}
