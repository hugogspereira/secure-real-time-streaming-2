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

        // -------------------------------------------------------
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
        properties.load(new FileInputStream(HS_CONFIG_FILE));
        String digitalSignature = checkProperty(properties, DIGITAL_SIGNATURE);
        String diffieHellman = checkProperty(properties, DIFFIE_HELLMAN);

        if(digitalSignature == null) {
            throw new Exception("Digital signatures option is not defined on the config file");
        }
        else if(diffieHellman != null) {
            handshake = new HandshakeDH(s, digitalSignature, diffieHellman, className, password, addr, addrToSend, configPass);
        }
        else {
            handshake = new HandshakeSE(s, digitalSignature, className, password, addr, addrToSend, configPass);
        }
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

    public void printBoxConfigStatus(int count, long afs, double totalTime) {
        handshake.printBoxConfigStatus(count,afs,totalTime);
    }

    public void printServerConfigStatus(int count, long afs, double totalTime, SocketAddress addr) throws IOException {
        send(new DatagramPacket(SafeDatagramSocket.CONTROL_MESSAGE, SafeDatagramSocket.CONTROL_MESSAGE.length, addr));

        handshake.printServerConfigStatus(count,afs,totalTime);
    }

    public DataInputStream decryptMovie(String encryptedConfig, String password) throws Exception {
        return (new DecryptMovie(handshake.getMovieName(), encryptedConfig, password).getDataInputStream());
    }
}
