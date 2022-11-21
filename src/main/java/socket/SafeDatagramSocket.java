package socket;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import util.ConfigReader;
import util.CryptoStuff;
import util.IntegrityFailedException;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Properties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import util.PrintStats;

public class SafeDatagramSocket {

    private static final String CIPHERSUITE = "CIPHERSUITE";
    private static final String KEY = "KEY";
    private static final String IV = "IV";
    private static final String INTEGRITY = "INTEGRITY";
    private static final String MACKEY = "MACKEY";
    public static final byte[] CONTROL_MESSAGE = new byte[1];
    public static final String DEFAULT_ADDRESS = "0.0.0.0:0000";

    private String addr;
    Properties properties;
    private DatagramSocket datagramSocket;

    public SafeDatagramSocket(SocketAddress addr, String config, String password) throws IOException {
        this.datagramSocket = new DatagramSocket();
        
        readProperties(addr, config, password);
    }

    public SafeDatagramSocket(InetSocketAddress addr, String boxConfig, String password) throws IOException {
        if(addr.getAddress().isMulticastAddress()){
            MulticastSocket datagramSocket = new MulticastSocket(addr.getPort());
            datagramSocket.joinGroup(addr, null); 
            this.datagramSocket = datagramSocket;
        }
        else 
            this.datagramSocket = new DatagramSocket();

        readProperties(addr, boxConfig, password);
    }

    private void readProperties(SocketAddress addr, String boxConfig, String password)
            throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        try {
            InputStream inputStream = new ByteArrayInputStream(
                    ConfigReader.read(boxConfig, addr.toString().split("/")[1], password).toByteArray());
            if (inputStream == null) {
                System.err.println("Configuration Box file not found!");
                System.exit(1);
            }
            properties = new Properties();
            properties.load(inputStream);

            this.addr = addr.toString();

        } catch (Exception e) {
            throw new IOException(e);
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
        byte[] cipherText = CryptoStuff.encrypt(data, size, properties);

        p.setData(cipherText);
        p.setLength(cipherText.length);
        return p;

    }

    public DatagramPacket decrypt(DatagramPacket p) throws IOException { // Decrypt
        byte[] movieData, data = p.getData();

        int size = p.getLength();
        
        try {
            movieData = CryptoStuff.decrypt(data, size, properties);
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
        String boxKey = checkProperty(properties, KEY);
        String boxIntegrity = checkProperty(properties, INTEGRITY);
        if (boxIntegrity == null)
            boxIntegrity = checkProperty(properties, MACKEY);
        PrintStats.toPrintBoxConfigStats(movieName, checkProperty(properties, CIPHERSUITE), boxKey, boxKey.length(), boxIntegrity);
        PrintStats.toPrintBoxStats(count, (double)afs/count, afs, totalTime, (double)count/totalTime, (double)afs*1000/totalTime);
    }

    public void printServerConfigStatus(String movieName, int count, long afs, double totalTime) {
        String boxKey = checkProperty(properties, KEY);
        String boxIntegrity = checkProperty(properties, INTEGRITY);
        if (boxIntegrity == null)
            boxIntegrity = checkProperty(properties, MACKEY);
        PrintStats.toPrintServerConfigStats(movieName, checkProperty(properties, CIPHERSUITE), boxKey, boxKey.length(), boxIntegrity);
        PrintStats.toPrintServerStats(count, (double)afs/count, afs, totalTime, (double)count/totalTime, (double)afs*1000/totalTime);
    }

}
