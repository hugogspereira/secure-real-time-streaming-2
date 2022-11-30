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
    private KeyPair keysDH;
    private String secureEnvelope;
    // -----------------------------------------------------
    private Cipher ciphersuite;
    private String ciphersuiteRTSP;
    private Mac hMac;
    // -----------------------------------------------------


    public SafeDatagramSocket(String className, String password, SocketAddress addr, String config) throws Exception {
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

    private void retrieveChosenAlgorithm(String cs) throws Exception {
        Properties ciphersuitesProperties = new Properties();
        ciphersuitesProperties.load(new FileInputStream(Utils.CIPHERSUITE_CONFIG_FILE));
        ciphersuiteRTSP = ciphersuitesProperties.getProperty(cs);
    }

    private void writeCiphersuitesAvailableBox(ObjectOutputStream oos) throws Exception {
        // Read the ciphersuites available for box
        String[] ciphersuites =  ConfigReader.readCiphersuites(PATH_TO_BOX_CONFIG, addr.toString().split("/")[1]);
        int ciphersuitesLength = ciphersuites.length;
        oos.write(ciphersuitesLength);
        // Array of ciphersuites
        for (String cipherString: ciphersuites) {
            oos.writeUTF(cipherString);
        }
    }

    private void writeCertificate(ObjectOutputStream oos) throws Exception {
        Certificate certificate = Utils.retrieveCertificateFromKeystore(PATH_TO_KEYSTORE+ fromClassName, password, fromClassName); // TODO
        int certificateLength = certificate.getEncoded().length;
        oos.write(certificateLength);
        oos.writeObject(certificate);
    }

    private void writeDHParametersBox(ObjectOutputStream oos, int dhParamKeyLen, PublicKey publicKeyDH, int dhParamPLen, BigInteger p, int dhParamGLen, BigInteger g) throws Exception {
        // Public Key DH - Box
        oos.write(dhParamKeyLen);
        oos.writeObject(publicKeyDH);
        // P
        oos.write(dhParamPLen);
        oos.writeObject(p);
        // G
        oos.write(dhParamGLen);
        oos.writeObject(g);
    }

    private void writeDigitalSignature(ObjectOutputStream oos, byte[] messageToSign) throws Exception {
        PrivateKey privateKey = Utils.retrievePrivateKeyFromKeystore(PATH_TO_KEYSTORE+ fromClassName, password, fromClassName); // TODO
        Cipher cipher = Cipher.getInstance(digitalSignature);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] signature = cipher.doFinal(messageToSign);
        oos.write(signature.length);
        oos.write(signature);
    }

    private void writeHash(ObjectOutputStream oos, byte[] message) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(message);
        oos.write(messageHash.length);
        oos.write(messageHash);
    }



    private byte[] generateSecretDHServer(BigInteger p, BigInteger g, PublicKey pubKey) throws Exception {
        DHParameterSpec dhParams = new DHParameterSpec(p, g);
        keysDH = Utils.generateDHKeys(diffieHellman, dhParams);

        return generateSecretDH(pubKey);
    }

    private byte[] generateSecretDH(PublicKey pubKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance(diffieHellman, "BC");
        keyAgree.init(keysDH.getPrivate());
        keyAgree.doPhase(pubKey, true);
        byte[] secretKey = keyAgree.generateSecret();

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        return md.digest(secretKey);
    }



    private void generateSymmetricKey(byte[] symmetricAndHmacKey, String[] cipherMode, int mode) throws Exception {
        byte[] symmetricKey = Arrays.copyOfRange(symmetricAndHmacKey,0, Integer.parseInt(cipherMode[1]));
        ciphersuite = Cipher.getInstance(cipherMode[0]);
        IvParameterSpec ivSpec = new IvParameterSpec(symmetricKey);
        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, cipherMode[0].split("/")[0]);
        ciphersuite.init(mode, secretKeySpec, ivSpec);
    }

    private void generateHMacKey(byte[] symmetricAndHmacKey, String[] cipherMode) throws Exception {
        int finalOffset = symmetricAndHmacKey.length;
        if(finalOffset-Integer.parseInt(cipherMode[1]) > 256) {
            finalOffset = Integer.parseInt(cipherMode[1])+256;
        }
        byte[] macKey = Arrays.copyOfRange(symmetricAndHmacKey,Integer.parseInt(cipherMode[1]), finalOffset);
        hMac = Mac.getInstance("HmacSHA256");
        Key hMacKey = new SecretKeySpec(macKey, "HmacSHA256"); //
        hMac.init(hMacKey);
    }


    private byte[] getBytesOfFirstMessage(int ciphersuiteLength, String[] boxCiphersuites, int certLength, byte[] certData,
                                          int yBoxLength, byte[] yBox, int pLength, byte[] pData, int gLength, byte[] gData,
                                          int signatureLength, byte[] signedBytes) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(ciphersuiteLength);
        for(int i = 0; i < ciphersuiteLength; i++) {
            bos.write(boxCiphersuites[i].getBytes());
        }
        bos.write(certLength);
        bos.write(certData);
        bos.write(yBoxLength);
        bos.write(yBox);
        bos.write(pLength);
        bos.write(pData);
        bos.write(gLength);
        bos.write(gData);
        bos.write(signatureLength);
        bos.write(signedBytes);
        return bos.toByteArray();
    }

    private byte[] getBytesOfSecondMessage(int ciphersuiteLength, byte[] csData, int certLength, byte[] certData,
                                          int yServerLength, byte[] yServer, int signatureLength, byte[] signedBytes) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(ciphersuiteLength);
        bos.write(csData);
        bos.write(certLength);
        bos.write(certData);
        bos.write(yServerLength);
        bos.write(yServer);
        bos.write(signatureLength);
        bos.write(signedBytes);
        return bos.toByteArray();
    }



    private byte[] getMessageToSignBox(int dhParamKeyLen, PublicKey publicKeyDH, int dhParamPLen, BigInteger p, int dhParamGLen, BigInteger g) throws Exception {
        ByteArrayOutputStream auxBos = new ByteArrayOutputStream();
        ObjectOutputStream auxOos = new ObjectOutputStream(auxBos);
        auxOos.writeObject(dhParamKeyLen);
        auxOos.writeObject(publicKeyDH);
        auxOos.writeObject(dhParamPLen);
        auxOos.writeObject(p);
        auxOos.writeObject(dhParamGLen);
        auxOos.writeObject(g);
        return auxBos.toByteArray();
    }



    public void createBoxHandshake(DatagramSocket inSocket) throws Exception {
        sendFirstMessageHS();
        receiveSecondMessageHS(inSocket);
        sendThirdMessageHS();
    }

    public void createServerHandshake(DatagramSocket inSocket) throws Exception {
        receiveFirstMessageHS(inSocket);
        sendSecondMessageHS();
        receiveThirdMessageHS(inSocket);
    }

    private void sendFirstMessageHS() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);

        // Read the ciphersuites available for box
        writeCiphersuitesAvailableBox(oos);

        // Certificate
        writeCertificate(oos);

        // DH Parameters Generation
        DHParameterSpec dhParams = Utils.generateDHParameters();
        keysDH = Utils.generateDHKeys(diffieHellman, dhParams);

        // PublicNum Box
        PublicKey publicKeyDH = keysDH.getPublic();
        int dhParamKeyLen = publicKeyDH.getEncoded().length;
        // P
        BigInteger p = dhParams.getP();
        int dhParamPLen = p.toByteArray().length;
        // G
        BigInteger g = dhParams.getG();
        int dhParamGLen = g.toByteArray().length;

        // Write the Dh Parameters
        writeDHParametersBox(oos, dhParamKeyLen, publicKeyDH, dhParamPLen, p, dhParamGLen, g);

        // Create the message that box will sign
        byte[] message2 = getMessageToSignBox(dhParamKeyLen, publicKeyDH, dhParamPLen, p, dhParamGLen, g);
        // Signature
        writeDigitalSignature(oos, message2);

        byte[] messageTotal = bos.toByteArray();
        // hash
        writeHash(oos, messageTotal);

        byte[] data = bos.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr);
        datagramSocket.send(packet);
    }

    private void receiveFirstMessageHS(DatagramSocket inSocket) throws Exception {
        DatagramPacket inPacket;
        byte[] buffer = new byte[10*1024]; // TODO - SIZE ???

        inPacket = new DatagramPacket(buffer, buffer.length);
        inSocket.receive(inPacket);

        DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(inPacket.getData()));

        // lista de ciphersuites
        int ciphersuiteLength = inputStream.readInt();
        String[] boxCiphersuites = new String[ciphersuiteLength];
        for(int i = 0; i < ciphersuiteLength; i++) {
            boxCiphersuites[i] = inputStream.readUTF();
        }
        ciphersuiteRTSP = chooseCommonCipher(boxCiphersuites, ConfigReader.readCiphersuites(PATH_TO_SERVER_CONFIG, addr.toString().split("/")[1]));

        // Certificate
        int certLength = inputStream.readInt();
        byte[] certData = inputStream.readNBytes(certLength);
        PublicKey publicKeyBox = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certData)).getPublicKey(); // TODO - Validar o certificado

        // Ybox
        int yBoxLength = inputStream.readInt();
        byte[] yBox = inputStream.readNBytes(yBoxLength);
        PublicKey boxPubKey = KeyFactory.getInstance(diffieHellman, "BC").generatePublic(new X509EncodedKeySpec(yBox)); // TODO
        // P
        int pLength = inputStream.readInt();
        byte[] pData = inputStream.readNBytes(pLength);
        BigInteger p = new BigInteger(pData);
        // G
        int gLength = inputStream.readInt();
        byte[] gData = inputStream.readNBytes(gLength);
        BigInteger g = new BigInteger(gData);


        // Message that was signed
        byte[] message2 = getMessageToSignBox(yBoxLength, boxPubKey, pLength, p,gLength,g);

        //Signature
        int signatureLength = inputStream.readInt();
        Cipher cipher = Cipher.getInstance(digitalSignature);
        cipher.init(Cipher.DECRYPT_MODE, publicKeyBox);

        // Byte Arrays that will be compared to see if its everything fine
        byte[] signedBytes = inputStream.readNBytes(signatureLength);
        byte[] dataSigned = cipher.doFinal(signedBytes);

        if(!dataSigned.equals(message2) ) {
            throw new Exception("Invalid signature! {Yserver || P || G} != Sig_kprivServer(Yserver || P || G)");
        }

        // Hash
        int hashLength = inputStream.readInt();
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // Generate the bytes
        byte[] messageTotal = getBytesOfFirstMessage(ciphersuiteLength, boxCiphersuites, certLength, certData,
                yBoxLength, yBox, pLength, pData, gLength, gData, signatureLength, signedBytes);

        // Byte Arrays that will be compared to see if its everything fine
        byte[] messageHash = md.digest(messageTotal);
        byte[] hash = inputStream.readNBytes(hashLength);

        if(!messageHash.equals(hash)) {
            throw new Exception("Message content have been changed!");
        }


        // -------------------------
        // Box - computations
        // -------------------------

        String[] cipherMode = ciphersuiteRTSP.split("-");
        // Generate the secret
        byte[] symmetricAndHmacKey = generateSecretDHServer(p,g,boxPubKey);
        // Parte vai para a chave simetrica
        generateSymmetricKey(symmetricAndHmacKey, cipherMode, Cipher.ENCRYPT_MODE);
        // Parte que vai para a chave HMAC
        generateHMacKey(symmetricAndHmacKey, cipherMode);
    }

    private void sendSecondMessageHS() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);

        // ciphersuite escolhida
        int ciphersuitesLength = ciphersuiteRTSP.length();
        oos.write(ciphersuitesLength);
        oos.write(ciphersuiteRTSP.getBytes());

        // Certificate
        writeCertificate(oos);

        // PublicNum Box
        int dhParamKeyLen = keysDH.getPublic().getEncoded().length;
        oos.write(dhParamKeyLen);
        oos.writeObject(keysDH.getPublic());

        // Create the message that server will sign
        byte[] message2 = keysDH.getPublic().getEncoded();
        // Signature
        writeDigitalSignature(oos,message2);

        byte[] messageTotal = bos.toByteArray();
        // hash
        writeHash(oos, messageTotal);

        byte[] data = bos.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr);
        datagramSocket.send(packet);
    }

    private void receiveSecondMessageHS(DatagramSocket inSocket) throws Exception {
        DatagramPacket inPacket;
        byte[] buffer = new byte[10*1024]; // TODO - SIZE ???

        inPacket = new DatagramPacket(buffer, buffer.length);
        inSocket.receive(inPacket);

        DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(inPacket.getData()));

        // Ciphersuite escolhida
        int ciphersuiteLength = inputStream.readInt();
        byte[] csData = inputStream.readNBytes(ciphersuiteLength);
        String cs = new String(csData);
        retrieveChosenAlgorithm(cs);

        // certificate
        int certLength = inputStream.readInt();
        byte[] certData = inputStream.readNBytes(certLength);
        PublicKey publicKeyServer = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certData)).getPublicKey(); // TODO - Validar o certificado

        // Yserver
        int yServerLength = inputStream.readInt();
        byte[] yServer = inputStream.readNBytes(yServerLength);
        PublicKey serverPubKey = KeyFactory.getInstance(diffieHellman, "BC").generatePublic(new X509EncodedKeySpec(yServer));  // TODO


        // Signature
        int signatureLength = inputStream.readInt();
        Cipher cipher = Cipher.getInstance(digitalSignature);
        cipher.init(Cipher.DECRYPT_MODE, publicKeyServer);

        // Byte Arrays that will be compared to see if its everything fine
        byte[] signedBytes = inputStream.readNBytes(signatureLength);
        byte[] dataSigned = cipher.doFinal(signedBytes);

        if(!yServer.equals(dataSigned)) {
            throw new Exception("Invalid signature! {Yserver} != Sig_kprivServer(Yserver)");
        }

        // Hash
        int hashLength = inputStream.readInt();
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // Generate the bytes
        byte[] messageTotal = getBytesOfSecondMessage(ciphersuiteLength,csData,certLength,certData,yServerLength,yServer,signatureLength,signedBytes);

        // Byte Arrays that will be compared to see if its everything fine
        byte[] messageHash = md.digest(messageTotal);
        byte[] hash = inputStream.readNBytes(hashLength);

        if(!messageHash.equals(hash)) {
            throw new Exception("Message content have been changed!");
        }


        // -------------------------
        // Server - computations
        // -------------------------

        String[] cipherMode = ciphersuiteRTSP.split("-");
        // Generate the secret
        byte[] symmetricAndHmacKey = generateSecretDH(serverPubKey);
        // Parte vai para a chave simetrica
        generateSymmetricKey(symmetricAndHmacKey, cipherMode, Cipher.DECRYPT_MODE);
        // Parte que vai para a chave HMAC
        generateHMacKey(symmetricAndHmacKey, cipherMode);
    }

    private void sendThirdMessageHS() {
        // TODO
    }

    private void receiveThirdMessageHS(DatagramSocket inSocket) {
        // TODO
    }

    private String chooseCommonCipher(String[] boxCiphersuites, String[] readCiphersuites) throws Exception {
        int comparator;
        for (int i = 0; i < readCiphersuites.length; i++) {
            for (int j = 0; j < boxCiphersuites.length; j++) {
                comparator = readCiphersuites[i].compareTo(boxCiphersuites[i]);
                if(comparator == 0) {
                    return readCiphersuites[i];
                }
                else if(comparator < 0){
                    break;
                }
            }
        }
        throw new Exception("Does not exist common ciphersuites between box and server");
    }
}
