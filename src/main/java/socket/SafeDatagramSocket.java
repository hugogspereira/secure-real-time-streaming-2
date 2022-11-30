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



    private PublicKey sendFirstMessageHS() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);

        String[] ciphersuites =  ConfigReader.readCiphersuites(PATH_TO_BOX_CONFIG, addr.toString().split("/")[1]);
        int ciphersuitesLength = ciphersuites.length;
        // Array of ciphersuites
        oos.write(ciphersuitesLength);
        // TODO - Falta ler o tamanho completo do array
        for (String cipherString: ciphersuites) {
            oos.writeUTF(cipherString);
        }

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

    private PublicKey receiveFirstMessageHS(DatagramSocket inSocket) throws Exception {
        DatagramPacket inPacket;
        byte[] buffer = new byte[10*1024]; // TODO - SIZE ???

        inPacket = new DatagramPacket(buffer, buffer.length);
        inSocket.receive(inPacket);
        DataInputStream inputStream = new DataInputStream(new ByteArrayInputStream(inPacket.getData()));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        // lista de ciphersuites
        int ciphersuiteLength = inputStream.readInt();
        bos.write(ciphersuiteLength);
        // Falta ler o tamanho completo do array
        String[] boxCiphersuites = new String[ciphersuiteLength];
        for(int i = 0; i < ciphersuiteLength; i++) {
            boxCiphersuites[i] = inputStream.readUTF();
            // escrever no bos
            bos.write(boxCiphersuites[i].getBytes());
        }
        ciphersuiteRTSP = chooseCommonCipher(boxCiphersuites, ConfigReader.readCiphersuites(PATH_TO_SERVER_CONFIG, addr.toString().split("/")[1]));

        // Certificate
        int certLength = inputStream.readInt();
        bos.write(certLength);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509"); // TODO
        byte[] certData = inputStream.readNBytes(certLength);
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certData));
        // TODO - Validar o certificado
        bos.write(certData);
        PublicKey publicKeyBox = cert.getPublicKey();

        ByteArrayOutputStream auxBos = new ByteArrayOutputStream();
        ObjectOutputStream auxOos = new ObjectOutputStream(auxBos);

        // Ybox
        int yBoxLength = inputStream.readInt();
        bos.write(yBoxLength);
        byte[] yBox = inputStream.readNBytes(yBoxLength);
        bos.write(yBox);
        X509EncodedKeySpec boxPubKeySpec = new X509EncodedKeySpec(yBox); // TODO
        KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
        PublicKey boxPubKey = keyFactory.generatePublic(boxPubKeySpec);
        auxOos.writeObject(boxPubKey);
        // P
        int pLength = inputStream.readInt();
        bos.write(pLength);
        byte[] pData = inputStream.readNBytes(pLength);
        BigInteger p = new BigInteger(pData);
        bos.write(pData);
        auxOos.writeObject(p);
        // G
        int gLength = inputStream.readInt();
        bos.write(gLength);
        byte[] gData = inputStream.readNBytes(gLength);
        BigInteger g = new BigInteger(gData);
        bos.write(gData);
        auxOos.writeObject(g);

        //Signature
        int signatureLength = inputStream.readInt();
        bos.write(signatureLength);
        Cipher cipher = Cipher.getInstance(digitalSignature);
        cipher.init(Cipher.DECRYPT_MODE, boxPubKey);
        byte[] signedBytes = inputStream.readNBytes(signatureLength);
        byte[] dataSigned = cipher.doFinal(signedBytes);
        bos.write(signedBytes);

        if(!dataSigned.equals(auxBos.toByteArray()) ) {
            throw new Exception("Invalid signature! {Yserver || P || G} != Sig_kprivServer(Yserver || P || G)");
        }

        int hashLength = inputStream.readInt();
        bos.write(hashLength);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(bos.toByteArray());

        byte[] hash = inputStream.readNBytes(hashLength);
        if(!messageHash.equals(hash)) {
            throw new Exception("Message content have been changed!");
        }

        // Generate the secret - TODO - está mal - onde é aplicado o P e o G ???
        KeyAgreement serverKeyAgree = KeyAgreement.getInstance(diffieHellman, "BC");
        PrivateKey serverPrivateKey = Utils.retrievePrivateKeyFromKeystore(PATH_TO_KEYSTORE+ fromClassName, password, fromClassName);
        serverKeyAgree.init(serverPrivateKey);
        serverKeyAgree.doPhase(publicKeyBox, true);
        byte[] secretKey = serverKeyAgree.generateSecret();
        // TODO

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

        return boxPubKey;
    }

    private void sendSecondMessageHS(PublicKey serverPublicKey) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);

        int ciphersuitesLength = ciphersuiteRTSP.length();
        // ciphersuite escolhida
        oos.write(ciphersuitesLength);
        oos.write(ciphersuiteRTSP.getBytes());

        Certificate certificate = Utils.retrieveCertificateFromKeystore(PATH_TO_KEYSTORE+ fromClassName, password, fromClassName); // TODO
        int certificateLength = certificate.getEncoded().length;
        // Certificate
        oos.write(certificateLength);
        oos.writeObject(certificate);

        ByteArrayOutputStream auxBos = new ByteArrayOutputStream();
        ObjectOutputStream auxOos = new ObjectOutputStream(auxBos);
        // PublicNum Box
        int dhParamKeyLen = serverPublicKey.getEncoded().length;
        oos.write(dhParamKeyLen);
        oos.writeObject(serverPublicKey);
        auxOos.writeObject(serverPublicKey);

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
        // TODO - Validar o certificado
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

    public void createServerHandshake(DatagramSocket inSocket) throws Exception {
        PublicKey serverPublicKey = receiveFirstMessageHS(inSocket);
        sendSecondMessageHS(serverPublicKey);
        receiveThirdMessageHS(inSocket);
    }

    private void receiveThirdMessageHS(DatagramSocket inSocket) {
        // TODO
    }

    private String chooseCommonCipher(String[] boxCiphersuites, String[] readCiphersuites) throws Exception {
        int comparator;
        for (int i = 0; i < boxCiphersuites.length; i++) {
            for (int j = 0; j < readCiphersuites.length; j++) {
                comparator = boxCiphersuites[i].compareTo(readCiphersuites[i]);
                if(comparator == 0) {
                    return boxCiphersuites[i];
                }
                else if(comparator > 0){
                    break;
                }
            }
        }
        throw new Exception("Does not exist common ciphersuites between box and server");
    }
}
