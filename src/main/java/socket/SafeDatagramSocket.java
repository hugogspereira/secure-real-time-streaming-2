package socket;

import util.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Properties;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static util.Utils.*;

public class SafeDatagramSocket {

    private static final String DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE";
    private static final String DIFFIE_HELLMAN = "DIFFIE_HELLMAN";
    private static final String SECURE_ENVELOPE = "SECURE_ENVELOPE";

    public static final byte[] CONTROL_MESSAGE = new byte[1];
    public static final String DEFAULT_ADDRESS = "0.0.0.0:0000";

    // -----------------------------------------------------
    private SocketAddress addr;
    private DatagramSocket datagramSocket;
    private String fromClassName;
    private String password;
    // -----------------------------------------------------
    private String digitalSignature;
    private String diffieHellman;
    private String secureEnvelope;
    // -----------------------------------------------------
    private Cipher ciphersuite;
    private String ciphersuiteRTSP;
    private Mac hMac;
    // -----------------------------------------------------


    public SafeDatagramSocket(String className, String password, SocketAddress addr, String config) throws IOException {
        this.datagramSocket = new DatagramSocket();

        readHandshakeProperties(className,password,addr);
        createServerHandshake(new DatagramSocket(addr));
    }

    public SafeDatagramSocket(DatagramSocket inSocket, String className, String password, InetSocketAddress addr, String boxConfig) throws Exception {
        // TODO - Suposto ser multicast ???
        if(addr.getAddress().isMulticastAddress()){
            MulticastSocket datagramSocket = new MulticastSocket(addr.getPort());
            datagramSocket.joinGroup(addr, null); 
            this.datagramSocket = datagramSocket;
        }
        else {
            this.datagramSocket = new DatagramSocket();
        }

        readHandshakeProperties(className,password,addr);
        createBoxHandshake(inSocket);
    }

    private void readHandshakeProperties(String className, String password, SocketAddress addr) throws IOException {
        Provider provider = Security.getProvider("BC");
        if (provider == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        this.fromClassName = className;
        this.password = password;
        this.addr = addr;

        try {
            Properties properties = new Properties();
            properties.load(new FileInputStream(HS_CONFIG_FILE));
            digitalSignature = checkProperty(properties, DIGITAL_SIGNATURE);
            diffieHellman = checkProperty(properties, DIFFIE_HELLMAN);
            secureEnvelope = checkProperty(properties, SECURE_ENVELOPE);
        }
        catch (Exception e) {
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
        // Note that this method can only be called by the server - cipher is init as ENCRYPT
        byte[] cipherText = CryptoStuff.encrypt(data, size, ciphersuite, hMac);

        p.setData(cipherText);
        p.setLength(cipherText.length);
        return p;

    }

    public DatagramPacket decrypt(DatagramPacket p) throws IOException { // Decrypt
        byte[] movieData, data = p.getData();

        int size = p.getLength();
        
        try {
            // Note that this method can only be called by the box - cipher is init as DECRYPT
            movieData = CryptoStuff.decrypt(data, size, ciphersuite, hMac);
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


    /*
     *************************************************************************************
     *************************************************************************************
     *                                     PHASE 2                                       *
     *************************************************************************************
     *************************************************************************************
     */



    private PublicKey sendFirstMessageHS() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);

        String[] ciphersuites =  ConfigReader.readCiphersuites(PATH_TO_BOX_CONFIG, addr.toString().split("/")[1]);
        int ciphersuitesLength = ciphersuites.length;
        // Array of ciphersuites
        oos.write(ciphersuitesLength);
        oos.writeObject(ciphersuites);

        Certificate certificate = Utils.retrieveCertificateFromKeystore(PATH_TO_KEYSTORE+ fromClassName, password, fromClassName); // TODO
        int certificateLength = certificate.getEncoded().length;
        // Certificate
        oos.write(certificateLength);
        oos.writeObject(certificate);

        DHParameterSpec dhParams = Utils.generateDHParameters();
        PublicKey publicKeyDH = Utils.generateDHKeys(dhParams).getPublic();
        ByteArrayOutputStream auxBos = new ByteArrayOutputStream();
        ObjectOutputStream auxOos = new ObjectOutputStream(auxBos);
        // PublicNum Box
        int dhParamKeyLen = publicKeyDH.getEncoded().length;
        oos.write(dhParamKeyLen);
        oos.writeObject(publicKeyDH);
        auxOos.writeObject(publicKeyDH);
        // P
        BigInteger p = dhParams.getP();
        int dhParamPLen = p.toByteArray().length;
        oos.write(dhParamPLen);
        oos.writeObject(p);
        auxOos.writeObject(p);
        // G
        BigInteger g = dhParams.getG();
        int dhParamGLen = g.toByteArray().length;
        oos.write(dhParamGLen);
        oos.writeObject(g);
        auxOos.writeObject(p);

        byte[] message1 = bos.toByteArray();
        byte[] message2 = auxBos.toByteArray();

        // Signature
        PrivateKey boxPrivateKey = Utils.retrievePrivateKeyFromKeystore(PATH_TO_KEYSTORE+ fromClassName, password, fromClassName); // TODO
        Cipher cipher = Cipher.getInstance(digitalSignature);
        cipher.init(Cipher.ENCRYPT_MODE, boxPrivateKey);
        byte[] signature = cipher.doFinal(message2);
        oos.write(signature.length);
        oos.write(signature);

        // hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        auxBos = new ByteArrayOutputStream();
        auxBos.write(message1);
        auxBos.write(message2);
        byte[] messageHash = md.digest(auxBos.toByteArray());
        oos.write(messageHash.length);
        oos.write(messageHash);

        byte[] data = bos.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr);
        datagramSocket.send(packet);

        return publicKeyDH;
    }

    private void receiveSecondMessageHS(DatagramSocket inSocket, PublicKey boxPublicKey) throws Exception {
        DatagramPacket inPacket;
        byte[] buffer = new byte[10*1024]; // TODO - SIZE ???

        inPacket = new DatagramPacket(buffer, buffer.length);
        inSocket.receive(inPacket);
        DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(inPacket.getData()));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        int ciphersuiteLength = inputStream.readInt();
        bos.write(ciphersuiteLength);
        Properties ciphersuitesProperties = new Properties();
        ciphersuitesProperties.load(new FileInputStream(Utils.CIPHERSUITE_CONFIG_FILE));
        byte[] csData = inputStream.readNBytes(ciphersuiteLength);
        String cs = new String(csData);
        bos.write(csData);
        ciphersuiteRTSP = ciphersuitesProperties.getProperty(cs);

        int certLength = inputStream.readInt();
        bos.write(certLength);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509"); // TODO
        byte[] certData = inputStream.readNBytes(certLength);
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certData));
        bos.write(certData);
        PublicKey publicKeyServer = cert.getPublicKey();

        int yServerLength = inputStream.readInt();
        bos.write(yServerLength);
        byte[] yServer = inputStream.readNBytes(yServerLength);
        bos.write(yServer);
        X509EncodedKeySpec serverPubKeySpec = new X509EncodedKeySpec(yServer); // TODO
        KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
        PublicKey serverPubKey = keyFactory.generatePublic(serverPubKeySpec);

        int signatureLength = inputStream.readInt();
        bos.write(signatureLength);
        Cipher cipher = Cipher.getInstance(digitalSignature);
        cipher.init(Cipher.DECRYPT_MODE, serverPubKey);
        byte[] signedBytes = inputStream.readNBytes(signatureLength);
        byte[] dataSigned = cipher.doFinal(signedBytes);
        bos.write(signedBytes);

        if(!yServer.equals(dataSigned)) {
            throw new Exception("Invalid signature! {Yserver} != Sig_kprivServer(Yserver)");
        }

        int hashLength = inputStream.readInt();
        bos.write(hashLength);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(bos.toByteArray());

        byte[] hash = inputStream.readNBytes(hashLength);
        if(!messageHash.equals(hash)) {
            throw new Exception("Message content have been changed!");
        }

        // Generate the secret
        KeyAgreement boxKeyAgree = KeyAgreement.getInstance(diffieHellman, "BC");
        boxKeyAgree.init(boxPublicKey);
        boxKeyAgree.doPhase(serverPubKey, true);
        byte[] secretKey = boxKeyAgree.generateSecret();

        md = MessageDigest.getInstance("SHA-512");
        byte[] symmetricAndHmacKey = md.digest(secretKey);

        // Parte vai para a chave simetrica
        String[] cipherMode = ciphersuiteRTSP.split("-");
        byte[] symmetricKey = Arrays.copyOfRange(symmetricAndHmacKey,0, Integer.parseInt(cipherMode[1]));
        ciphersuite = Cipher.getInstance(cipherMode[0]);
        IvParameterSpec ivSpec = new IvParameterSpec(symmetricKey);
        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, cipherMode[0].split("/")[0]);
        ciphersuite.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        // Parte que vai para a chave HMAC
        int finalOffset = symmetricAndHmacKey.length;
        if(finalOffset-Integer.parseInt(cipherMode[1]) > 256) {
            finalOffset = Integer.parseInt(cipherMode[1])+256;
        }
        byte[] macKey = Arrays.copyOfRange(symmetricAndHmacKey,Integer.parseInt(cipherMode[1]), finalOffset);
        hMac = Mac.getInstance("HmacSHA256");
        Key hMacKey = new SecretKeySpec(macKey, "HmacSHA256"); //
        hMac.init(hMacKey);
    }

    private void sendThirdMessageHS() {
        // TODO
    }

    public void createBoxHandshake(DatagramSocket inSocket) throws Exception {
        PublicKey boxPublicKey = sendFirstMessageHS();
        receiveSecondMessageHS(inSocket, boxPublicKey);
        sendThirdMessageHS();
    }

    public void createServerHandshake(DatagramSocket inSocket) throws SocketException {
        receiveFirstMessageHS(inSocket);
        sendSecondMessageHS();
        receiveThirdMessageHS(inSocket);
    }

    private void receiveFirstMessageHS(DatagramSocket inSocket) {

    }

    private void sendSecondMessageHS() {
    }

    private void receiveThirdMessageHS(DatagramSocket inSocket) {
    }
}
