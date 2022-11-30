package socket;

import util.*;
import java.io.*;
import java.net.*;
import java.util.Properties;

import static util.Utils.*;

public class SafeDatagramSocket {

    private static final String DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE";
    private static final String DIFFIE_HELLMAN = "DIFFIE_HELLMAN";
    private static final String SECURE_ENVELOPE = "SECURE_ENVELOPE";

    public static final byte[] CONTROL_MESSAGE = new byte[1];
    public static final String DEFAULT_ADDRESS = "0.0.0.0:0000";

    // -----------------------------------------------------
    private DatagramSocket datagramSocket;
    private Handshake handshake;
    // -----------------------------------------------------


    public SafeDatagramSocket(String className, String password, SocketAddress addr) throws Exception {
        this.datagramSocket = new DatagramSocket();

        handshakeCreation(datagramSocket, className, password, addr);
        handshake.createServerHandshake(new DatagramSocket(addr));
    }

    public SafeDatagramSocket(DatagramSocket inSocket, String className, String password, InetSocketAddress addr) throws Exception {      // TODO - Suposto ser multicast ???
        if(addr.getAddress().isMulticastAddress()){
            MulticastSocket datagramSocket = new MulticastSocket(addr.getPort());
            datagramSocket.joinGroup(addr, null); 
            this.datagramSocket = datagramSocket;
        }
        else {
            this.datagramSocket = new DatagramSocket();
        }

        handshakeCreation(datagramSocket, className, password, addr);
        handshake.createBoxHandshake(inSocket);
    }

    private void handshakeCreation(DatagramSocket datagramSocket, String className, String password, SocketAddress addr) throws Exception {
        Properties properties = new Properties();
        properties.load(new FileInputStream(HS_CONFIG_FILE));
        String digitalSignature = checkProperty(properties, DIGITAL_SIGNATURE);
        String diffieHellman = checkProperty(properties, DIFFIE_HELLMAN);
        String secureEnvelope = checkProperty(properties, SECURE_ENVELOPE);

        if(digitalSignature == null) {
            throw new Exception("Digital signatures option is not defined on the config file");
        }
        else if(diffieHellman != null) {
            handshake = new HandshakeDH(datagramSocket, digitalSignature, diffieHellman, className, password, addr);
        }
        else if(secureEnvelope != null) {
            handshake = new HandshakeSE();  // TODO - Secure Envelopes
        }
        else {
            throw new Exception("Neither Diffie Hellman, neither secure envelopes option is defined");
        }
    }

    private String checkProperty(Properties properties, String property) {
        String res = properties.getProperty(property);
        if (res.equalsIgnoreCase("NULL")) {
            res = null;
        }
        return res;
    }

    public DatagramPacket encrypt(DatagramPacket p) throws IOException { // Encrypt
        byte[] data = p.getData();

        int size = data.length;
        // Note that this method can only be called by the server - cipher is init as ENCRYPT
        byte[] cipherText = CryptoStuff.encrypt(data, size, handshake.getCipher(), handshake.getHMac());

        p.setData(cipherText);
        p.setLength(cipherText.length);
        return p;

    }

    public DatagramPacket decrypt(DatagramPacket p) throws IOException { // Decrypt
        byte[] movieData, data = p.getData();

        int size = p.getLength();
        
        try {
            // Note that this method can only be called by the box - cipher is init as DECRYPT
            movieData = CryptoStuff.decrypt(data, size, handshake.getCipher(), handshake.getHMac());
        } catch (IntegrityFailedException e) {
            return null;
        }

        p.setData(movieData);
        p.setLength(movieData.length);
        return p;

    }

    public void send(DatagramPacket p, SocketAddress addr) throws IOException {
        p.setSocketAddress(addr);
        datagramSocket.send(p);
    }

    public void send(DatagramPacket p) throws IOException {
        datagramSocket.send(p);
    }

    public void printBoxConfigStatus(String movieName, int count, long afs, double totalTime) {
        /* TODO
        String boxKey = ciphersuite.getAlgorithm();
        String boxIntegrity = checkProperty(properties, INTEGRITY);
        if (boxIntegrity == null)
            boxIntegrity = checkProperty(properties, MACKEY);
        PrintStats.toPrintBoxConfigStats(movieName, checkProperty(properties, CIPHERSUITE), boxKey, boxKey.length(), boxIntegrity);
        PrintStats.toPrintBoxStats(count, (double)afs/count, afs, totalTime, (double)count/totalTime, (double)afs*1000/totalTime);
        */
    }

    public void printServerConfigStatus(String movieName, int count, long afs, double totalTime) {
        /* TODO
        String boxKey = checkProperty(properties, KEY);
        String boxIntegrity = checkProperty(properties, INTEGRITY);
        if (boxIntegrity == null)
            boxIntegrity = checkProperty(properties, MACKEY);
        PrintStats.toPrintServerConfigStats(movieName, checkProperty(properties, CIPHERSUITE), boxKey, boxKey.length(), boxIntegrity);
        PrintStats.toPrintServerStats(count, (double)afs/count, afs, totalTime, (double)count/totalTime, (double)afs*1000/totalTime);
        */
    }

}
