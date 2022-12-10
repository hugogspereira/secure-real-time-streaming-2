package socket;

import util.ConfigReader;
import util.Utils;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;
import static util.Utils.*;

public class HandshakeDH implements Handshake {

	private static final String HMAC_ALGORITHM = "HmacSHA256";
	private SocketAddress addr;
	private SocketAddress addrToSend;
	private OutputStream out;
	private InputStream in;
	private String fromClassName;
	private String password;
	// ---------------------------------------------
	private String digitalSignature;
	private String diffieHellman;
	private KeyPair keysDH;
	// ---------------------------------------------
	private Cipher ciphersuite;
	private String ciphersuiteRTSP;
	private Mac hMac; // for the symmetric encryption
	private Mac hMacHS; // for the HS

	public HandshakeDH(Socket socket, String digitalSignature, String diffieHellman, String className, String password, SocketAddress addr, SocketAddress addrToSend) throws Exception {
		this.digitalSignature = digitalSignature;
		this.diffieHellman = diffieHellman;
		this.fromClassName = className;
		this.password = password;
		this.addr = addr;
		this.out = socket.getOutputStream();
		this.in = socket.getInputStream();
		this.addrToSend = addrToSend;
		initiateHMAC();
	}

	private void initiateHMAC() throws Exception {
		Properties preSharedHMAC = new Properties();
		preSharedHMAC.load(new FileInputStream(PRESHARED_CONFIG_FILE));
		String hmacKey;
		if(fromClassName.equals("hjStreamServer")) {
			hmacKey = preSharedHMAC.getProperty(addrToSend.toString().split("/")[1].replace(":","-"));
		}
		else {
			hmacKey = preSharedHMAC.getProperty(addr.toString().split("/")[1].replace(":","-"));
		}

		hMacHS = Mac.getInstance(HMAC_ALGORITHM);
		Key hMacKey = new SecretKeySpec(hmacKey.getBytes(), HMAC_ALGORITHM);
		hMacHS.init(hMacKey);
	}

	private void retrieveChosenAlgorithm(String cs) throws Exception {
		Properties ciphersuitesProperties = new Properties();
		ciphersuitesProperties.load(new FileInputStream(Utils.CIPHERSUITE_CONFIG_FILE));
		ciphersuiteRTSP = ciphersuitesProperties.getProperty(cs);
	}

	private void writeCiphersuitesAvailableBox(ObjectOutputStream oos) throws Exception {
		// Read the ciphersuites available for box
		String[] ciphersuites =  ConfigReader.readCiphersuites(PATH_TO_BOX_CONFIG, addr.toString().split("/")[1]);
		int ciphersuitesLength = ciphersuites.length;
		oos.writeInt(ciphersuitesLength);
		oos.flush();
		// Array of ciphersuites
		for (String cipherString: ciphersuites) {
			oos.writeUTF(cipherString);
			oos.flush();
		}
	}

	private void writeCertificate(ObjectOutputStream oos) throws Exception {

		Certificate certificate = Utils.retrieveCertificateFromKeystore(PATH_TO_KEYSTORE, password, fromClassName);
		oos.writeObject(certificate);
		oos.flush();
	}

	private void writeDHParametersBox(ObjectOutputStream oos, PublicKey publicKeyDH, BigInteger p, BigInteger g) throws Exception {
		// Public Key DH - Box
		oos.writeObject(publicKeyDH);
		oos.flush();
		// P
		oos.writeObject(p);
		oos.flush();
		// G
		oos.writeObject(g);
		oos.flush();
	}

	private void writeDigitalSignature(ObjectOutputStream oos, byte[] message) throws Exception {
		PrivateKey privateKey = Utils.retrievePrivateKeyFromKeystore(PATH_TO_KEYSTORE, password, fromClassName); // TODO

		//HASH
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		byte[] messageToSign = md.digest(message);


		Signature sig = Signature.getInstance(digitalSignature.split("-")[0],"BC");
		sig.initSign(privateKey);
		sig.update(messageToSign);
		byte[] signature = sig.sign();
		oos.writeInt(signature.length);
		oos.flush();
		oos.write(signature);
		oos.flush();
	}

	private void writeHMac(ObjectOutputStream oos, byte[] message) throws Exception {
		// HMAC
		hMacHS.update(message);
		byte[] integrityData = hMacHS.doFinal();
		oos.writeInt(integrityData.length);
		oos.flush();
		oos.write(integrityData);
		oos.flush();
	}



	private byte[] generateSecretDHServer(BigInteger p, BigInteger g, PublicKey pubKey) throws Exception {
		DHParameterSpec dhParams = new DHParameterSpec(p, g);
		keysDH = Utils.generateDHKeys(diffieHellman.split("-")[0], dhParams);

		return generateSecretDH(pubKey);
	}

	private byte[] generateSecretDH(PublicKey pubKey) throws Exception {
		KeyAgreement keyAgree = KeyAgreement.getInstance(diffieHellman.split("-")[0], "BC");
		keyAgree.init(keysDH.getPrivate());
		keyAgree.doPhase(pubKey, true);
		byte[] secretKey = keyAgree.generateSecret();

		MessageDigest md = MessageDigest.getInstance("SHA-512");
		return md.digest(secretKey);
	}



	private void generateSymmetricKey(byte[] symmetricAndHmacKey, String[] cipherMode, int mode) throws Exception {
		byte[] symmetricKey = Arrays.copyOfRange(symmetricAndHmacKey,0, Integer.parseInt(cipherMode[1])/Byte.SIZE);
		ciphersuite = Cipher.getInstance(cipherMode[0]);
		String modeCipher = cipherMode[0].split("/")[1];
		IvParameterSpec ivSpec = null;
		if(modeCipher.equals("CCM")) {
			ivSpec = new IvParameterSpec(Arrays.copyOfRange(symmetricKey,0,7));   // 7 a 13 bytes
		}
		else {
			// ...
		}
		SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, cipherMode[0].split("/")[0]);
		ciphersuite.init(mode, secretKeySpec, ivSpec);
	}

	private void generateHMacKey(byte[] symmetricAndHmacKey, String[] cipherMode) throws Exception {
		int finalOffset = symmetricAndHmacKey.length;

		if(finalOffset-(Integer.parseInt(cipherMode[1])/Byte.SIZE) > (256/Byte.SIZE)) {
			finalOffset = (Integer.parseInt(cipherMode[1])/Byte.SIZE) + (256/Byte.SIZE);
		}
		byte[] macKey = Arrays.copyOfRange(symmetricAndHmacKey,(Integer.parseInt(cipherMode[1])/Byte.SIZE), finalOffset);

		hMac = Mac.getInstance(HMAC_ALGORITHM);
		Key hMacKey = new SecretKeySpec(macKey, HMAC_ALGORITHM);
		hMac.init(hMacKey);
	}

	private byte[] getBytesOfFirstMessage(int ciphersuiteLength, String[] boxCiphersuites, X509Certificate cert,
										  PublicKey pKeyBox, BigInteger p, BigInteger g,
										  int signatureLength, byte[] signedBytes) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		oos.writeInt(ciphersuiteLength);
		oos.flush();
		for(int i = 0; i < ciphersuiteLength; i++) {
			oos.writeUTF(boxCiphersuites[i]);
			oos.flush();
		}
		oos.writeObject(cert);
		oos.flush();
		oos.writeObject(pKeyBox);
		oos.flush();
		oos.writeObject(p);
		oos.flush();
		oos.writeObject(g);
		oos.flush();
		oos.writeInt(signatureLength);
		oos.flush();
		oos.write(signedBytes);
		oos.flush();

		return bos.toByteArray();
	}

	private byte[] getBytesOfSecondMessage(String cs,X509Certificate cert, PublicKey serverPubKey, int signatureLength, byte[] signedBytes) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream auxOos = new ObjectOutputStream(bos);
		auxOos.writeUTF(cs);
		auxOos.flush();
		auxOos.writeObject(cert);
		auxOos.flush();
		auxOos.writeObject(serverPubKey);
		auxOos.flush();
		auxOos.writeInt(signatureLength);
		auxOos.flush();
		auxOos.write(signedBytes);
		auxOos.flush();
		return bos.toByteArray();
	}


	private byte[] getBytesOfPublicKey(PublicKey pubKey) throws Exception {
		ByteArrayOutputStream auxBos = new ByteArrayOutputStream();
		ObjectOutputStream auxOos = new ObjectOutputStream(auxBos);
		auxOos.writeObject(pubKey);
		auxOos.flush();
		return auxBos.toByteArray();
	}

	private byte[] getMessageToSignBox(PublicKey publicKeyDH, BigInteger p, BigInteger g) throws Exception {
		ByteArrayOutputStream auxBos = new ByteArrayOutputStream();
		ObjectOutputStream auxOos = new ObjectOutputStream(auxBos);
		auxOos.writeObject(publicKeyDH);
		auxOos.flush();
		auxOos.writeObject(p);
		auxOos.flush();
		auxOos.writeObject(g);
		auxOos.flush();
		return auxBos.toByteArray();
	}

	private void waitForTheSend() throws Exception {
		while(in.available() == 0) { }
		System.out.println("recebi pacote - vou avançar");
	}


	@Override
	public Cipher getCipher() {
		return ciphersuite;
	}

	@Override
	public Mac getHMac() {
		return hMac;
	}

	public void createBoxHandshake() throws Exception {
		sendFirstMessageHS();
		receiveSecondMessageHS();
		sendThirdMessageHS();
	}

	public void createServerHandshake() throws Exception {
		receiveFirstMessageHS();
		sendSecondMessageHS();
		receiveThirdMessageHS();
	}

	private void sendFirstMessageHS() throws Exception {
		System.out.println("vou enviar 1 MSG");

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		// Read the ciphersuites available for box
		writeCiphersuitesAvailableBox(oos);

		// Certificate
		writeCertificate(oos);

		// DH Parameters Generation
		String[] dhs = diffieHellman.split("-");
		String dh = dhs[0];
		String dhKeys = dhs[1];

		DHParameterSpec dhParams = Utils.generateDHParameters(dhKeys);
		keysDH = Utils.generateDHKeys(dh, dhParams);

		// PublicNum Box
		PublicKey publicKeyDH = keysDH.getPublic();
		// P
		BigInteger p = dhParams.getP();
		// G
		BigInteger g = dhParams.getG();

		// Write the Dh Parameters
		writeDHParametersBox(oos, publicKeyDH, p, g);

		// Create the message that box will sign
		byte[] message2 = getMessageToSignBox(publicKeyDH, p, g);
		// Signature
		writeDigitalSignature(oos, message2);

		byte[] messageTotal = bos.toByteArray();
		// HMAC
		writeHMac(oos, messageTotal);

		byte[] data = bos.toByteArray();
		out.write(data);

		System.out.println("ENVIEI 1 MSG "+data.length);
		System.out.println("---------------------");
	}

	private void receiveFirstMessageHS() throws Exception {
		System.out.println("RECEBER 1 MSG");
		DataInputStream inputStream = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(inputStream);

		// Waits until the box sends the message
		waitForTheSend();

		// lista de ciphersuites
		int ciphersuiteLength = ois.readInt();
		System.out.println(ciphersuiteLength);
		String[] boxCiphersuites = new String[ciphersuiteLength];
		for(int i = 0; i < ciphersuiteLength; i++) {
			boxCiphersuites[i] = ois.readUTF();
			System.out.println(boxCiphersuites[i]);
		}
		Properties ciphersuitesProperties = new Properties();
		ciphersuitesProperties.load(new FileInputStream(Utils.CIPHERSUITE_CONFIG_FILE));
		ciphersuiteRTSP = ciphersuitesProperties.getProperty(chooseCommonCipher(boxCiphersuites, ConfigReader.readCiphersuites(PATH_TO_SERVER_CONFIG, addrToSend.toString().split("/")[1])));

		// Certificate
		X509Certificate cert = (X509Certificate) ois.readObject();
		try {  // TODO
			validateCertificate(cert);
		}
		catch(Exception e) {
			e.printStackTrace();
		}

		PublicKey publicKeyBox = cert.getPublicKey();

		// Ybox
		PublicKey boxPubKey = (PublicKey) ois.readObject();
		// P
		BigInteger p = (BigInteger) ois.readObject();
		// G
		BigInteger g = (BigInteger) ois.readObject();

		//Signature
		int signatureLength = ois.readInt();
		byte[] signedBytes = ois.readNBytes(signatureLength);

		Security.addProvider(new BouncyCastleProvider());
		Signature sig = Signature.getInstance(digitalSignature.split("-")[0],"BC");
		sig.initVerify(publicKeyBox);
		if(sig.verify(signedBytes)) {
			throw new Exception("Invalid signature!   != Sig_kprivServer(Yserver || P || G)");
		}

		// Generate the bytes
		byte[] messageTotal = getBytesOfFirstMessage(ciphersuiteLength,boxCiphersuites,cert,boxPubKey,p,g,signatureLength,signedBytes);

		// HMAC
		int hmacLength = ois.readInt();
		byte[] hmac = ois.readNBytes(hmacLength);

		// Byte Arrays that will be compared to see if it is everything fine
		hMacHS.update(messageTotal);
		byte[] messageHMAC = hMacHS.doFinal();

		if(!MessageDigest.isEqual(messageHMAC, hmac)) {
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

		System.out.println("RECEBI 1 MSG");
		System.out.println("---------------------");
	}

	
	private void sendSecondMessageHS() throws Exception {
		System.out.println("VOU ENVIAR 2 MSG");
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		// ciphersuite escolhida
		oos.writeUTF(ciphersuiteRTSP);
		oos.flush();

		// Certificate
		writeCertificate(oos);

		// PublicNum Server
		PublicKey dhPublickeyServer = keysDH.getPublic();
		oos.writeObject(dhPublickeyServer);
		oos.flush();
		
		// Create the message that server will sign
		byte[] message2 = getBytesOfPublicKey(dhPublickeyServer);
		// Signature
		writeDigitalSignature(oos,message2);

		byte[] messageTotal = bos.toByteArray();
		// hash
		writeHMac(oos, messageTotal);
		
		byte[] data = bos.toByteArray();
		out.write(data);

		System.out.println("ENVIEI 2 MSG");
		System.out.println("---------------------");
	}
	
	private void receiveSecondMessageHS() throws Exception {
		System.out.println("Vou receber 2 MSG");
		DataInputStream inputStream = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(inputStream);

		waitForTheSend();

		// Ciphersuite escolhida
		String cs = ois.readUTF();
		ciphersuiteRTSP = cs;

		// certificate
		X509Certificate cert = (X509Certificate) ois.readObject();
		try {  // TODO
			validateCertificate(cert);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		PublicKey publicKeyServer = cert.getPublicKey();
		
		// Yserver
		PublicKey serverPubKey = (PublicKey) ois.readObject();
		
		// Signature
		int signatureLength = ois.readInt();
		// Byte Arrays that will be compared to see if its everything fine
		byte[] signedBytes = ois.readNBytes(signatureLength);

		Signature sig = Signature.getInstance(digitalSignature.split("-")[0],"BC");
		sig.initVerify(publicKeyServer);
		if(sig.verify(signedBytes)) {
			throw new Exception("Invalid signature!   != Sig_kprivServer(Yserver || P || G)");
		}

		// Generate the bytes
		byte[] messageTotal = getBytesOfSecondMessage(cs,cert,serverPubKey,signatureLength,signedBytes);

		// HMAC
		int hmacLength = ois.readInt();
		byte[] hmacData = ois.readNBytes(hmacLength);

		// Byte Arrays that will be compared to see if it is everything fine
		hMacHS.update(messageTotal);
		byte[] messageHMAC = hMacHS.doFinal();

		if(!MessageDigest.isEqual(messageHMAC, hmacData)) {
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
		System.out.println("RECEBI 2 MSG");
		System.out.println("---------------------");
	}
	
	private void sendThirdMessageHS() throws Exception {
		// TODO
	}
	
	private void receiveThirdMessageHS()  throws Exception {
		// TODO
		Thread.sleep(7500);  // just to have time for box to recover
	}
	
	/**
	 * Validates certificate by verifying it and checking date
	 * @param cert - certificate being validated
	 */
	private void validateCertificate(X509Certificate cert) throws Exception {
		try {		
			Date currentDate = new Date();
			cert.checkValidity(currentDate);
			cert.verify(Utils.retrieveCACertificate(PATH_TO_KEYSTORE, password, fromClassName).getPublicKey());
		} catch (CertificateNotYetValidException e){
			throw new CertificateNotYetValidException("Certificate not in valid date!!!");
		} catch (SignatureException e) {
			throw new SignatureException("Not the right key!!!");
		}
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
