package socket;

import crypto.PBEFileDecryption;
import util.ConfigReader;
import util.CryptoStuff;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
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
import static util.UtilsCertificateManipulation.*;
import static util.UtilsObjectManipulation.*;
import static util.UtilsSEManipulation.*;

public class HandshakeSE implements Handshake {

	private static final String HMAC_ALGORITHM = "HmacSHA256";
	private static final String SHA_ALGORITHM = "SHA-512";


	private final SocketAddress addr, addrToSend;
	private final OutputStream out;
	private final InputStream in;
	private final String fromClassName, certPassword;  // name to retrieve the certificate and the password
	private String movieName;
	// ---------------------------------------------
	private final String digitalSignature, secureEnvelope;
	private PublicKey otherPartPublicKey;
	private PrivateKey random;
	private String ciphersuiteRTSP; // for the HS
	private Mac hMacHS; // for the HS
	// ---------------------------------------------
	private Cipher ciphersuite; // for the symmetric encryption
	private byte[] symmetricAndHmacKey; // data for the ciphersuite
	private Mac hMac; // for the symmetric encryption
	//----------------------------------------------
	private String configPass; //password for config files


	public HandshakeSE(Socket socket, String digitalSignature, String secureEnvelope, String className, String certPassword, SocketAddress addr, SocketAddress addrToSend, String configPass) throws Exception {
		this.digitalSignature = digitalSignature;
		this.secureEnvelope = secureEnvelope;
		this.fromClassName = className;
		this.certPassword = certPassword;

		this.addr = addr;
		this.addrToSend = addrToSend;

		this.configPass = configPass;

		this.out = socket.getOutputStream();
		this.in = socket.getInputStream();

		initiateHMAC();
	}

	private void initiateHMAC() throws Exception {
		Properties preSharedHMAC = new Properties();
		preSharedHMAC.load(PBEFileDecryption.decryptFiles(configPass, PRESHARED_CONFIG_FILE));

		String hmacKey;
		if(fromClassName.equals(HJSTREAMSERVER)) {
			hmacKey = preSharedHMAC.getProperty(getPropertyNameFromAddress(addrToSend));
		}
		else {
			hmacKey = preSharedHMAC.getProperty(getPropertyNameFromAddress(addr));
		}

		hMacHS = Mac.getInstance(HMAC_ALGORITHM);
		Key hMacKey = new SecretKeySpec(hmacKey.getBytes(), HMAC_ALGORITHM);
		hMacHS.init(hMacKey);
	}



	@Override
	public Cipher getCipher() {
		return ciphersuite;
	}

	@Override
	public Mac getHMac() {
		return hMac;
	}

	@Override
	public String getMovieName() {
		return movieName;
	}



	public void createBoxHandshake(String movieName) throws Exception {
		this.movieName = movieName;
		sendFirstMessageHS();
		receiveSecondMessageHS();
		sendThirdMessageHS();
		receiveForthMessageHS();
		sendFifthMessageHS(movieName);
	}

	public void createServerHandshake() throws Exception {
		receiveFirstMessageHS();
		sendSecondMessageHS();
		receiveThirdMessageHS();
		sendForthMessageHS();
		this.movieName = receiveFifthMessageHS();
	}

	private void sendFirstMessageHS() throws Exception {
		System.out.println("Vou enviar 1a msg");

		sendCertificate();

		System.out.println("Enviei 1a msg");
		System.out.println("---------------------");
	}

	private void receiveFirstMessageHS() throws Exception {
		System.out.println("Vou receber 1a msg");

		receiveCertificate();

		System.out.println("Recebi 1a msg");
		System.out.println("---------------------");
	}

	private void sendSecondMessageHS() throws Exception {
		System.out.println("Vou enviar 2a msg");

		sendCertificate();

		System.out.println("Enviei 2a msg");
		System.out.println("---------------------");
	}

	private void receiveSecondMessageHS() throws Exception {
		System.out.println("Vou receber 2a msg");

		receiveCertificate();

		System.out.println("Recebi 2a msg");
		System.out.println("---------------------");
	}

	private void sendThirdMessageHS() throws Exception {
		System.out.println("Vou enviar 3a msg");

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		// Read the ciphersuites available for box
		writeCiphersuitesAvailableBox(oos);

		// SE Parameters Generation
		String[] secEnvelopeSpecs = secureEnvelope.split("-");
		random = generateSERandom(secEnvelopeSpecs[0], secEnvelopeSpecs[1]);
		// TODO - secureEnvelope

		// Create the message that box will sign
		byte[] message2 = null;
		// Signature
		writeDigitalSignature(oos, message2);

		byte[] messageTotal = bos.toByteArray();
		// HMAC
		writeHMacHS(oos, messageTotal);

		byte[] data = bos.toByteArray();
		out.write(data);

		System.out.println("Enviei 3a msg");
		System.out.println("---------------------");
	}

	private void receiveThirdMessageHS() throws Exception {
		System.out.println("Recebi 3a msg");
		DataInputStream inputStream = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(inputStream);

		// Waits until the box sends the message
		waitForTheSend();

		// lista de ciphersuites
		int ciphersuiteLength = ois.readInt();
		String[] boxCiphersuites = new String[ciphersuiteLength];
		for(int i = 0; i < ciphersuiteLength; i++) {
			boxCiphersuites[i] = ois.readUTF();
		}
		Properties ciphersuitesProperties = new Properties();
		ciphersuitesProperties.load(PBEFileDecryption.decryptFiles(configPass, CIPHERSUITE_CONFIG_FILE));
		ciphersuiteRTSP = ciphersuitesProperties.getProperty(chooseCommonCipher(boxCiphersuites, ConfigReader.readCiphersuites(PATH_TO_SERVER_CONFIG, addrToSend.toString().split("/")[1])));

		// TODO - secure envelope
		// ...

		//Signature
		int signatureLength = ois.readInt();
		byte[] signedBytes = ois.readNBytes(signatureLength);

		Signature sig = Signature.getInstance(digitalSignature.split("-")[0],"BC");
		sig.initVerify(otherPartPublicKey);
		if(sig.verify(signedBytes)) {
			throw new Exception("Invalid signature!   != Sig_kprivServer(Yserver || P || G)");
		}

		// Generate the bytes
		byte[] messageTotal = null;

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
		// Generate the secret - from where it will be extracted the symetric key and the HMAC key
		symmetricAndHmacKey = generateSecretSE();
		// Parte que vai para a chave HMAC
		generateHMacKey(symmetricAndHmacKey, cipherMode);

		System.out.println("Recebi 3a msg");
		System.out.println("---------------------");
	}


	private void sendForthMessageHS() throws Exception {
		System.out.println("Vou enviar 4a msg");
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		// ciphersuite escolhida
		oos.writeUTF(ciphersuiteRTSP);
		oos.flush();

		String[] secEnvelopeSpecs = secureEnvelope.split("-");
		random = generateSERandom(secEnvelopeSpecs[0], secEnvelopeSpecs[1]);
		// TODO - secureEnvelope

		// Create the message that server will sign
		byte[] message2 = null;
		// Signature
		writeDigitalSignature(oos,message2);

		byte[] messageTotal = bos.toByteArray();
		// hash
		writeHMacHS(oos, messageTotal);

		byte[] data = bos.toByteArray();
		out.write(data);

		System.out.println("Enviei 2a msg");
		System.out.println("---------------------");
	}

	private void receiveForthMessageHS() throws Exception {
		System.out.println("Vou receber 2 msg");
		DataInputStream inputStream = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(inputStream);

		waitForTheSend();

		// Ciphersuite escolhida
		String cs = ois.readUTF();
		ciphersuiteRTSP = cs;

		// TODO - Secure Envelope

		// Signature
		int signatureLength = ois.readInt();
		// Byte Arrays that will be compared to see if its everything fine
		byte[] signedBytes = ois.readNBytes(signatureLength);

		Signature sig = Signature.getInstance(digitalSignature.split("-")[0],"BC");
		sig.initVerify(otherPartPublicKey);
		if(sig.verify(signedBytes)) {
			throw new Exception("Invalid signature!   != Sig_kprivServer(Yserver || P || G)");
		}

		// Generate the bytes
		byte[] messageTotal = null;

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
		// Generate the secret - from where it will be extracted the symmetric key and the HMAC key
		symmetricAndHmacKey = generateSecretSE();
		// Parte que vai para a chave HMAC
		generateHMacKey(symmetricAndHmacKey, cipherMode);
		System.out.println("Recebi 2a msg");
		System.out.println("---------------------");
	}

	private void sendFifthMessageHS(String movieName) throws Exception {
		System.out.println("Vou enviar 3a msg");
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		byte[] movieNameData = movieName.getBytes();
		// Encrypted Message
		byte[] movieNameEncrypted = getMovieNameEncrypted(movieNameData);

		// movieName - control message
		oos.writeInt(movieNameEncrypted.length);
		oos.flush();
		oos.write(movieNameEncrypted);
		oos.flush();

		// hash
		writeHMac(oos, movieNameData);

		out.write(bos.toByteArray());
		System.out.println("Enviei 3a msg");
		System.out.println("---------------------");
	}

	private String receiveFifthMessageHS()  throws Exception {
		System.out.println("Vou receber 3a msg");
		DataInputStream is = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(is);

		waitForTheSend();

		byte[] movieNameEncrypted = ois.readNBytes(ois.readInt());
		// Decrypted Message
		byte[] movieNameData = getMovieNameDecrypted(movieNameEncrypted);

		// HMAC
		int hmacLength = ois.readInt();
		byte[] hmacData = ois.readNBytes(hmacLength);

		// Byte Arrays that will be compared to see if it is everything fine
		hMac.update(movieNameData);
		byte[] messageHMAC = hMac.doFinal();

		if(!MessageDigest.isEqual(messageHMAC, hmacData)) {
			throw new Exception("Message content have been changed!");
		}

		System.out.println("Recebi 3a msg");
		System.out.println("---------------------");
		return new String(movieNameData);
	}

	private void sendCertificate() throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		// Certificate
		writeCertificate(oos);

		byte[] messageTotal = bos.toByteArray();
		// HMAC
		writeHMacHS(oos, messageTotal);

		byte[] data = bos.toByteArray();
		out.write(data);
	}

	private void receiveCertificate() throws Exception {
		DataInputStream inputStream = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(inputStream);

		// Waits until the box sends the message
		waitForTheSend();

		// Certificate
		X509Certificate cert = (X509Certificate) ois.readObject();
		validateCertificate(cert);
		otherPartPublicKey = cert.getPublicKey();

		// Generate the bytes
		byte[] messageTotal = getBytesOfFirstMessageSE(cert);

		// HMAC
		int hmacLength = ois.readInt();
		byte[] hmac = ois.readNBytes(hmacLength);

		// Byte Arrays that will be compared to see if it is everything fine
		hMacHS.update(messageTotal);
		byte[] messageHMAC = hMacHS.doFinal();

		if(!MessageDigest.isEqual(messageHMAC, hmac)) {
			throw new Exception("Message content have been changed!");
		}
	}

	// -----------------------------------------------------------------------
	// Auxiliary methods to write and read the objects sent in the DH Protocol
	// -----------------------------------------------------------------------

	private void writeCiphersuitesAvailableBox(ObjectOutputStream oos) throws Exception {
		// Read the ciphersuites available for box
		String[] ciphersuites =  ConfigReader.readCiphersuites(PATH_TO_BOX_CONFIG, removeSlashFromAddress(addr));
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
		Certificate certificate = retrieveCertificateFromKeystore(PATH_TO_KEYSTORE, certPassword, fromClassName);
		oos.writeObject(certificate);
		oos.flush();
	}

	private void writeDigitalSignature(ObjectOutputStream oos, byte[] message) throws Exception {
		PrivateKey privateKey = retrievePrivateKeyFromKeystore(PATH_TO_KEYSTORE, certPassword, fromClassName);

		//HASH
		MessageDigest md = MessageDigest.getInstance(SHA_ALGORITHM);
		byte[] messageToSign = md.digest(message);

		Signature sig = Signature.getInstance(getAlgorithmFromConfigString(digitalSignature),"BC");
		sig.initSign(privateKey);
		sig.update(messageToSign);
		byte[] signature = sig.sign();

		oos.writeInt(signature.length);
		oos.flush();
		oos.write(signature);
		oos.flush();
	}

	private void writeHMacHS(ObjectOutputStream oos, byte[] message) throws Exception {
		hMacHS.update(message);
		byte[] integrityData = hMacHS.doFinal();

		oos.writeInt(integrityData.length);
		oos.flush();
		oos.write(integrityData);
		oos.flush();
	}

	private void writeHMac(ObjectOutputStream oos, byte[] message) throws Exception {
		hMac.update(message);
		byte[] integrityData = hMac.doFinal();

		oos.writeInt(integrityData.length);
		oos.flush();
		oos.write(integrityData);
		oos.flush();
	}

	// ------------------------------------------------------------------------------
	// Auxiliary methods to generate the secrets of Server and Box in the DH Protocol
	// ------------------------------------------------------------------------------

	private byte[] generateSecretSE() throws Exception {
		 return null;		//TODO
	}

	private byte[] generateCiphersuiteExtractMovieName(byte[] symmetricAndHmacKey, String[] cipherMode, int mode1, int mode2, byte[] movieNameData) throws Exception {
		byte[] symmetricKey = Arrays.copyOfRange(symmetricAndHmacKey,0, transformFromBitsToBytes(Integer.parseInt(cipherMode[1])));

		String transformation = cipherMode[0];  // Ex: AES/CCM/NoPadding
		ciphersuite = Cipher.getInstance(transformation);
		String modeCipher = removeSlashFromString(transformation);

		IvParameterSpec ivSpec = null;
		if(modeCipher.equals(CCM_MODE)) {
			ivSpec = new IvParameterSpec(Arrays.copyOfRange(symmetricKey,0,7));   // 7 a 13 bytes
		}
		else {
			// ...
		}

		SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, cipherMode[0].split(DELIMITER_ADDRESS)[0]);   // Ex: AES
		ciphersuite.init(mode1, secretKeySpec, ivSpec);

		byte[] movieNameFinalData;
		if(Cipher.DECRYPT_MODE == mode1) {
			movieNameFinalData = CryptoStuff.decrypt(movieNameData, movieNameData.length, ciphersuite, hMac);
		}
		else { // Encrypt
			movieNameFinalData = CryptoStuff.encrypt(movieNameData, movieNameData.length, ciphersuite, hMac);
		}

		ciphersuite.init(mode2, secretKeySpec, ivSpec);

		return movieNameFinalData;
	}

	private void generateHMacKey(byte[] symmetricAndHmacKey, String[] cipherMode) throws Exception {
		int finalOffset = symmetricAndHmacKey.length;

		if((finalOffset-transformFromBitsToBytes(Integer.parseInt(cipherMode[1]))) > transformFromBitsToBytes(256)) {
			finalOffset = transformFromBitsToBytes(Integer.parseInt(cipherMode[1])) + transformFromBitsToBytes(256);
		}
		byte[] macKey = Arrays.copyOfRange(symmetricAndHmacKey, transformFromBitsToBytes(Integer.parseInt(cipherMode[1])), finalOffset);

		hMac = Mac.getInstance(HMAC_ALGORITHM);
		Key hMacKey = new SecretKeySpec(macKey, HMAC_ALGORITHM);
		hMac.init(hMacKey);
	}

	// ---------------------------------------------------------------------------------------------------------
	// Auxiliary methods to instantiate the ciphersuite from the previously generated secrets in the DH Protocol
	// ---------------------------------------------------------------------------------------------------------

	private byte[] getMovieNameEncrypted(byte[] movieNameData) throws Exception {
		return generateCiphersuiteExtractMovieName(symmetricAndHmacKey,  ciphersuiteRTSP.split("-"), Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE, movieNameData);
	}

	private byte[] getMovieNameDecrypted(byte[] movieNameEncrypted) throws Exception {
		return generateCiphersuiteExtractMovieName(symmetricAndHmacKey,  ciphersuiteRTSP.split("-"), Cipher.DECRYPT_MODE, Cipher.ENCRYPT_MODE, movieNameEncrypted);
	}

	// --------------------------------------------------------------------------------
	// Auxiliary method to wait for the message of the other entity of the DH Protocol
	// --------------------------------------------------------------------------------

	private void waitForTheSend() throws Exception {
		while(in.available() == 0) {
			// Meter thread sleep para n gastar cpu ?
		}
		System.out.println("*** recebi pacote - vou avançar ***");
	}

	// -----------------------------------------------------------------------------------
	// Auxiliary method to validate the certificate of the other entity in the DH Protocol
	// -----------------------------------------------------------------------------------

	/**
	 * Validates certificate by verifying it and checking date
	 * @param cert - certificate being validated
	 */
	private void validateCertificate(X509Certificate cert) throws Exception {
		try {
			Date currentDate = new Date();
			cert.checkValidity(currentDate);
			cert.verify(retrieveCACertificate(PATH_TO_KEYSTORE, certPassword, fromClassName).getPublicKey());
		} catch (CertificateNotYetValidException e){
			throw new CertificateNotYetValidException("Certificate not in valid date!!!");
		} catch (SignatureException e) {
			throw new SignatureException("Not the right key!!!");
		}
	}

	// --------------------------------------------------------------------
	// Auxiliary method to choose the common ciphersuite in the DH Protocol
	// --------------------------------------------------------------------

	private String chooseCommonCipher(String[] boxCiphersuites, String[] readCiphersuites) throws Exception {
		int comparator;
		for (int i = 0; i < readCiphersuites.length; i++) {
			for (int j = 0; j < boxCiphersuites.length; j++) {
				comparator = readCiphersuites[i].compareTo(boxCiphersuites[j]);
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

