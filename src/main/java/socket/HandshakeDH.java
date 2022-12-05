package socket;

import util.ConfigReader;
import util.Utils;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Properties;
import static util.Utils.*;

public class HandshakeDH implements Handshake {

	private static final String HMAC_ALGORITHM = "HmacSHA256";
	private SocketAddress addr;
	private DatagramSocket datagramSocket;
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

	public HandshakeDH(DatagramSocket datagramSocket, String digitalSignature, String diffieHellman, String className, String password, SocketAddress addr) throws Exception {
		this.digitalSignature = digitalSignature;
		this.diffieHellman = diffieHellman;
		this.fromClassName = className;
		this.password = password;
		this.addr = addr;
		this.datagramSocket = datagramSocket;
		initiateHMAC();
	}

	private void initiateHMAC() throws Exception {
		Properties preSharedHMAC = new Properties();
		preSharedHMAC.load(new FileInputStream(PRESHARED_CONFIG_FILE));
		String hmacKey = preSharedHMAC.getProperty(addr.toString().split("/")[1].replace(":","-"));

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
		oos.write(ciphersuitesLength);
		// Array of ciphersuites
		for (String cipherString: ciphersuites) {
			oos.writeUTF(cipherString);
		}
	}

	private void writeCertificate(ObjectOutputStream oos) throws Exception {

		Certificate certificate = Utils.retrieveCertificateFromKeystore(PATH_TO_KEYSTORE + fromClassName, password, fromClassName);
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

	private void writeHMac(ObjectOutputStream oos, byte[] message) throws Exception {
		/*
		HASH
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] messageHash = md.digest(message);
		oos.write(messageHash.length);
		oos.write(messageHash);
		*/

		// HMAC
		hMac.update(message);
		byte[] integrityData = hMac.doFinal();
		oos.write(integrityData.length);
		oos.write(integrityData);
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
		hMac = Mac.getInstance(HMAC_ALGORITHM);
		Key hMacKey = new SecretKeySpec(macKey, HMAC_ALGORITHM); //
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


	@Override
	public Cipher getCipher() {
		return ciphersuite;
	}

	@Override
	public Mac getHMac() {
		return hMac;
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
		// HMAC
		writeHMac(oos, messageTotal);

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
		X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certData));
		validateCertificate(cert);
		PublicKey publicKeyBox = cert.getPublicKey();

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


		// HMAC
		int hmacLength = inputStream.readInt();

		// Generate the bytes
		byte[] messageTotal = getBytesOfFirstMessage(ciphersuiteLength, boxCiphersuites, certLength, certData,
				yBoxLength, yBox, pLength, pData, gLength, gData, signatureLength, signedBytes);

		// Byte Arrays that will be compared to see if it is everything fine
		hMac.update(messageTotal);
		byte[] messageHMAC = hMac.doFinal();
		byte[] hmac = inputStream.readNBytes(hmacLength);

		if(!messageHMAC.equals(hmac)) {
			// MessageDigest.isEqual(messageHMAC, hmac)
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
		writeHMac(oos, messageTotal);
		
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
		X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certData));
		validateCertificate(cert);
		PublicKey publicKeyServer = cert.getPublicKey();
		
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
		
		// HMAC
		int hmacLength = inputStream.readInt();
		
		// Generate the bytes
		byte[] messageTotal = getBytesOfSecondMessage(ciphersuiteLength,csData,certLength,certData,yServerLength,yServer,signatureLength,signedBytes);
		
		// Byte Arrays that will be compared to see if it is everything fine
		hMac.update(messageTotal);
		byte[] messageHMAC = hMac.doFinal();
		byte[] hmac = inputStream.readNBytes(hmacLength);
		
		if(!messageHMAC.equals(hmac)) {
			// MessageDigest.isEqual(messageHMAC, hmac)
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
	
	/**
	 * validades certificate by verifing it and chicking date
	 * @param cert - certificate being validated
	 * @throws Exception
	 */
	private void validateCertificate(X509Certificate cert) throws Exception {
		try {		
			Date currentDate = new Date();
			cert.checkValidity(currentDate);
			if(fromClassName.equals("hjBox"))
				cert.verify(Utils.retrieveCertificateFromKeystore(PATH_TO_KEYSTORE, password, "boxkeys").getPublicKey());
			else
				cert.verify(Utils.retrieveCertificateFromKeystore(PATH_TO_KEYSTORE, password, "serverkeys").getPublicKey()); 

			} catch (CertificateNotYetValidException e){
				throw new CertificateNotYetValidException("Certificate not in valid date!!!");
			} catch (SignatureException e) {
				throw new SignatureException("Not the right key!!!");
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
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
