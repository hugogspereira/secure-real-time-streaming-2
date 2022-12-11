package socket;

import crypto.DecryptMovie;
import crypto.PBEFileDecryption;
import util.*;
import java.io.*;
import java.net.*;
import java.util.Properties;

import static util.Utils.*;

public class SafeDatagramSocket {

    public static final byte[] CONTROL_MESSAGE = new byte[1];
    public static final String DEFAULT_ADDRESS = "0.0.0.0:0000";

    // -----------------------------------------------------
    private DatagramSocket datagramSocket;
    private Handshake handshake;
    // -----------------------------------------------------


    // HJSTREAMSERVER
    public SafeDatagramSocket(String className, String password, SocketAddress addr, String configPass) throws Exception {
        Properties properties = new Properties();
        properties.load(PBEFileDecryption.decryptFiles(configPass, SERVER_CONFIG_FILE));
        String[] addrServer = checkProperty(properties, "remote").split(":");
        SocketAddress addrServerSA = new InetSocketAddress(addrServer[0], Integer.parseInt(addrServer[1]));

        this.datagramSocket = new DatagramSocket();

        ServerSocket ss = new ServerSocket(Integer.parseInt(addr.toString().split(":")[1]));
        Socket s = ss.accept();

        handshakeCreation(s, className, password, addrServerSA, addr, configPass);
        handshake.createServerHandshake();
    }

    //HJBOX
    public SafeDatagramSocket(DatagramSocket inSocket, String className, String password, InetSocketAddress addr, String addressServer, String movieName, String configPass) throws Exception {
        String[] addrServer = addressServer.split(":");
        SocketAddress addrServerSA = new InetSocketAddress(addrServer[0], Integer.parseInt(addrServer[1]));

        // TODO ---------------------------------------------------
        if(addr.getAddress().isMulticastAddress()){
            MulticastSocket datagramSocket = new MulticastSocket(addr.getPort());
            datagramSocket.joinGroup(addr, null);
            this.datagramSocket = datagramSocket;
        }
        else {
            this.datagramSocket = new DatagramSocket();
        }
        // -------------------------------------------------------

        Socket s = new Socket("localhost", 9999);

        handshakeCreation(s, className, password, addr, addrServerSA, configPass);
        handshake.createBoxHandshake(movieName);
    }

    private void handshakeCreation(Socket s, String className, String password, SocketAddress addr, SocketAddress addrToSend, String configPass) throws Exception {
        Properties properties = new Properties();
        properties.load(PBEFileDecryption.decryptFiles(configPass, HS_CONFIG_FILE));
        String digitalSignature = checkProperty(properties, DIGITAL_SIGNATURE);
        String diffieHellman = checkProperty(properties, DIFFIE_HELLMAN);
        String secureEnvelope = checkProperty(properties, SECURE_ENVELOPE);

        if(digitalSignature == null) {
            throw new Exception("Digital signatures option is not defined on the config file");
        }
        else if(diffieHellman != null) {
            handshake = new HandshakeDH(s, digitalSignature, diffieHellman, className, password, addr, addrToSend, configPass);
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

    public DataInputStream decryptMovie(String encryptedConfig, String password) throws Exception {
        return (new DecryptMovie(handshake.getMovieName(), encryptedConfig, password).getDataInputStream());
    }
}
