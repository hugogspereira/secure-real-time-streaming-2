package socket;

import util.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.List;
import java.util.Properties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.spec.DHParameterSpec;
import static util.Utils.PATH_TO_KEYSTORE;

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
    private String keystoreName;
    private String password;

    public SafeDatagramSocket(String keyStore, String password, SocketAddress addr, String config) throws IOException {
        this.datagramSocket = new DatagramSocket();
        this.keystoreName = keyStore;
        this.password = password;
        
        readProperties(addr, config);
    }

    public SafeDatagramSocket(String keyStore, String password, InetSocketAddress addr, String boxConfig) throws IOException {
        if(addr.getAddress().isMulticastAddress()){
            MulticastSocket datagramSocket = new MulticastSocket(addr.getPort());
            datagramSocket.joinGroup(addr, null); 
            this.datagramSocket = datagramSocket;
        }
        else {
            this.datagramSocket = new DatagramSocket();
        }

        this.keystoreName = keyStore;
        this.password = password;

        readProperties(addr, boxConfig);
    }

    private void readProperties(SocketAddress addr, String boxConfig)
            throws IOException {
        Provider provider = Security.getProvider("BC");
        if (provider == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
            InputStream inputStream = new ByteArrayInputStream(
                    ConfigReader.read(boxConfig, addr.toString().split("/")[1]).toByteArray());
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


    /*
     *************************************************************************************
     *************************************************************************************
     *                                     PHASE 2                                       *
     *************************************************************************************
     *************************************************************************************
     */



    private void sendFirstMessageHS() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);

        List<String> ciphersuites =  ConfigReader.readCiphersuites(PATH_TO_KEYSTORE+keystoreName, addr.toString().split("/")[1]);
        int ciphersuitesLength = ciphersuites.toArray().length;
        oos.write(ciphersuitesLength); // Será que isto funciona ? Devia ser assim ?
        oos.writeObject(ciphersuites);

        /*
        // TODO - será isto ???????
        Certificate certificate = Utils.retrieveCertificateFromKeystore(PATH_TO_KEYSTORE+keystoreName, password, "aliasEntry");
        int certificateLength = certificate.getEncoded().length;
        oos.write(certificateLength); //
        oos.writeObject(certificate); //
        */

        // TODO - Para já estou só a apensar em DH, depois tentamos generalizar, o q achas?
        DHParameterSpec dhParams = Utils.generateDHParameters();
        KeyPair pair = Utils.generateDHKeys(dhParams);

        int dhParamsLen = pair.getPublic().getEncoded().length;
        oos.write(dhParamsLen); //
        oos.writeObject(pair.getPublic());
        dhParamsLen = dhParams.getP().toByteArray().length;
        oos.write(dhParamsLen); //
        oos.writeObject(dhParams.getP());
        dhParamsLen = dhParams.getG().toByteArray().length;
        oos.write(dhParamsLen); //
        oos.writeObject(dhParams.getG());

        // TODO
        // ...
        // Signature and hash
        // ...
    }

    private void receiveSecondMessageHS(DatagramSocket inSocket) throws Exception {
        DatagramPacket inPacket;
        byte[] buffer = new byte[5*1024]; // SIZE ???

        inPacket = new DatagramPacket(buffer, buffer.length);
        inSocket.receive(inPacket);
        DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(inPacket.getData()));

        int movieNameLength = inputStream.readInt();
        String movieName =  new String(inputStream.readNBytes(movieNameLength));

        int ciphersuitelength = inputStream.readInt();
        String ciphersuite = new String(inputStream.readNBytes(ciphersuitelength));

        int certLength = inputStream.readInt();
        // Certificado ? - como deserialize
        // ...

    }

    public void createBoxHandshake(DatagramSocket inSocket) throws Exception {
        sendFirstMessageHS();
        receiveSecondMessageHS(inSocket);

    }

    public void createServerHandshake(DatagramSocket inSocket) throws SocketException {
        // ...
    }
}
