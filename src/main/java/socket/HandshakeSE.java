package socket;

import crypto.PBEFileDecryption;
import util.ConfigReader;
import util.CryptoStuff;
import util.PrintStats;
import util.Utils;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Properties;

import static util.Utils.*;
import static util.UtilsCertificateManipulation.*;
import static util.UtilsObjectManipulation.*;
import static util.UtilsSEManipulation.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HandshakeSE implements Handshake {

	private final SocketAddress addr, addrToSend;
	private final OutputStream out;
	private final InputStream in;
	private final String fromClassName, certPassword;  // name to retrieve the certificate and the password
	private String movieName;
	// ---------------------------------------------
	private final String digitalSignature;
	private PublicKey otherPartPublicKey;
	private byte[] random;
	private String ciphersuiteRTSP; // for the HS
	private Mac hMacHS; // for the HS
	// ---------------------------------------------
	private Cipher ciphersuite; // for the symmetric encryption
	private byte[] symmetricAndHmacKey; // data for the ciphersuite
	private Mac hMac; // for the symmetric encryption
	//----------------------------------------------
	private String configPass; //password for config files


	public HandshakeSE(Socket socket, String digitalSignature, String className, String certPassword, SocketAddress addr, SocketAddress addrToSend, String configPass) throws Exception {
		Security.addProvider(new BouncyCastleProvider());

		this.digitalSignature = digitalSignature;
		this.fromClassName = className;
		this.certPassword = certPassword;

		this.addr = addr;
		this.addrToSend = addrToSend;

		this.configPass = configPass;

		this.out = socket.getOutputStream();
		this.in = socket.getInputStream();

		this.random = generateSERandom(32);

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

	@Override
	public void printBoxConfigStatus(int count, long afs, double totalTime) {
		byte[] key = Arrays.copyOfRange(symmetricAndHmacKey,0, transformFromBitsToBytes(Integer.parseInt(ciphersuiteRTSP.split(DELIMITER_CONFIG)[1])));
		String[] movie = movieName.split(DELIMITER_ADDRESS);
		String moviename = movie[movie.length-1].split(".encrypted")[0];
		PrintStats.toPrintBoxConfigStats(moviename, ciphersuite.getAlgorithm(), Base64.getEncoder().encodeToString(key), key.length*Byte.SIZE, HMAC_ALGORITHM);
		PrintStats.toPrintBoxStats(count, (double)afs/count, afs, totalTime, (double)count/totalTime, (double)afs*1000/totalTime);
	}

	@Override
	public void printServerConfigStatus(int count, long afs, double totalTime) {
		byte[] key = Arrays.copyOfRange(symmetricAndHmacKey,0, transformFromBitsToBytes(Integer.parseInt(ciphersuiteRTSP.split(DELIMITER_CONFIG)[1])));
		String[] movie = movieName.split(DELIMITER_ADDRESS);
		String moviename = movie[movie.length-1].split(".encrypted")[0];
		PrintStats.toPrintServerConfigStats(moviename, ciphersuite.getAlgorithm(), Base64.getEncoder().encodeToString(key), key.length*Byte.SIZE, HMAC_ALGORITHM);
		PrintStats.toPrintServerStats(count, (double)afs/count, afs, totalTime, (double)count/totalTime, (double)afs*1000/totalTime);
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
		writeRandomSEParameter(oos);

		// Create the message that box will sign
		byte[] message2 = random;
		// Signature
		writeDigitalSignature(oos, message2);

		byte[] messageTotal = bos.toByteArray();
		// HMAC
		writeHMacHS(oos, messageTotal);

		out.write(bos.toByteArray());

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
		ciphersuitesProperties.load(new FileInputStream(CIPHERSUITE_CONFIG_FILE));
		ciphersuiteRTSP = ciphersuitesProperties.getProperty(chooseCommonCipher(boxCiphersuites, ConfigReader.readCiphersuites(PATH_TO_SERVER_CONFIG, addrToSend.toString().split(DELIMITER_ADDRESS)[1])));

		byte[][] envolope = readRandomSEParameter(ois);
		byte[] receivedRandom = envolope[0];
		byte[] keyBlock = envolope[1];
		byte[] cipheredRandom = envolope[2];

		//Signature
		int signatureLength = ois.readInt();
		byte[] signedBytes = ois.readNBytes(signatureLength);

		Signature sig = Signature.getInstance(digitalSignature.split(DELIMITER_CONFIG)[0],"BC");
		sig.initVerify(otherPartPublicKey);
		if(sig.verify(signedBytes)) {
			throw new Exception("Invalid signature!   != Sig_kprivServer(Random_box)");
		}

		// Generate the bytes
		byte[] messageTotal = getBytesOfThirdMessageSE(ciphersuiteLength,boxCiphersuites,keyBlock.length,keyBlock, cipheredRandom.length, cipheredRandom,signatureLength,signedBytes);

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

		String[] cipherMode = ciphersuiteRTSP.split(DELIMITER_CONFIG);
		// Generate the secret - from where it will be extracted the symmetric key and the HMAC key
		symmetricAndHmacKey = generateSecretSE(receivedRandom);
		for (byte b:symmetricAndHmacKey) {
			System.out.println(b);
		}
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

		writeRandomSEParameter(oos);

		// Create the message that server will sign
		byte[] message2 = random;
		// Signature
		writeDigitalSignature(oos,message2);

		byte[] messageTotal = bos.toByteArray();
		// hash
		writeHMacHS(oos, messageTotal);

		out.write(bos.toByteArray());

		System.out.println("Enviei 4a msg");
		System.out.println("---------------------");
	}

	private void receiveForthMessageHS() throws Exception {
		System.out.println("Vou receber 4a msg");
		DataInputStream inputStream = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(inputStream);

		waitForTheSend();

		// Ciphersuite escolhida
		ciphersuiteRTSP = ois.readUTF();

		byte[][] envolope = readRandomSEParameter(ois);
		byte[] receivedRandom = envolope[0];
		byte[] keyBlock = envolope[1];
		byte[] cipheredRandom = envolope[2];


		// Signature
		int signatureLength = ois.readInt();
		// Byte Arrays that will be compared to see if its everything fine
		byte[] signedBytes = ois.readNBytes(signatureLength);

		Signature sig = Signature.getInstance(digitalSignature.split(DELIMITER_CONFIG)[0],"BC");
		sig.initVerify(otherPartPublicKey);
		if(sig.verify(signedBytes)) {
			throw new Exception("Invalid signature!   != Sig_kprivServer(Random_server)");
		}

		// Generate the bytes
		byte[] messageTotal = getBytesOfForthMessageSE(ciphersuiteRTSP,keyBlock.length,keyBlock, cipheredRandom.length, cipheredRandom, signatureLength,signedBytes);

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

		String[] cipherMode = ciphersuiteRTSP.split(DELIMITER_CONFIG);
		// Generate the secret - from where it will be extracted the symmetric key and the HMAC key
		symmetricAndHmacKey = generateSecretSE(receivedRandom);
		for (byte b:symmetricAndHmacKey) {
			System.out.println(b);
		}
		// Parte que vai para a chave HMAC
		generateHMacKey(symmetricAndHmacKey, cipherMode);
		System.out.println("Recebi 4a msg");
		System.out.println("---------------------");
	}

	

	private void sendFifthMessageHS(String movieName) throws Exception {
		System.out.println("Vou enviar 5a msg");
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

		byte[] messageTotal = bos.toByteArray();
		// hash
		writeHMac(oos, messageTotal);

		out.write(bos.toByteArray());
		System.out.println("Enviei 5a msg");
		System.out.println("---------------------");
	}

	private String receiveFifthMessageHS()  throws Exception {
		System.out.println("Vou receber 5a msg");
		DataInputStream is = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(is);

		waitForTheSend();

		int movieLength = ois.readInt();
		byte[] movieNameEncrypted = ois.readNBytes(movieLength);

		// Decrypted Message
		byte[] movieNameData = getMovieNameDecrypted(movieNameEncrypted);

		// HMAC
		int hmacLength = ois.readInt();
		byte[] hmacData = ois.readNBytes(hmacLength);

		// Generate the bytes
		byte[] messageTotal = getBytesOfFifthMessageSE(movieLength,movieNameEncrypted);

		// Byte Arrays that will be compared to see if it is everything fine
		hMac.update(messageTotal);
		byte[] messageHMAC = hMac.doFinal();

		if(!MessageDigest.isEqual(messageHMAC, hmacData)) {
			throw new Exception("Message content have been changed!");
		}

		System.out.println("Recebi 5a msg");
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

	private void writeRandomSEParameter(ObjectOutputStream oos) throws Exception {
		byte r[]=new byte[16];
		SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(r);
        IvParameterSpec sIvSpec = new IvParameterSpec(r);
		Key sKey = Utils.createKeyForAES(256, secureRandom);
		
		Cipher xCipher = Cipher.getInstance(getAlgorithmFromConfigString(digitalSignature),"BC");
        xCipher.init(Cipher.ENCRYPT_MODE, otherPartPublicKey, secureRandom);
        byte[] keyBlock = xCipher.doFinal(Utils.packKeyAndIv(sKey, sIvSpec));

		Cipher sCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		sCipher.init(Cipher.ENCRYPT_MODE, sKey, sIvSpec);

        byte[] cipheredRandom = sCipher.doFinal(random);

		oos.writeInt(keyBlock.length);
		oos.flush();
		oos.write(keyBlock);
		oos.flush();

		oos.writeInt(cipheredRandom.length);
		oos.flush();
		oos.write(cipheredRandom);
		oos.flush();
	}
	
	private byte[][] readRandomSEParameter(ObjectInputStream ois) throws Exception {
		
		int keyBlockLen = ois.readInt();
		byte[] keyBlock = ois.readNBytes(keyBlockLen);
		int cipheredRandomLen = ois.readInt();
		byte[] cipheredRandom = ois.readNBytes(cipheredRandomLen);


		Cipher xCipher = Cipher.getInstance(getAlgorithmFromConfigString(digitalSignature),"BC");
		xCipher.init(Cipher.DECRYPT_MODE, retrievePrivateKeyFromKeystore(PATH_TO_KEYSTORE, certPassword, fromClassName));
        Object[] keyIv = Utils.unpackKeyAndIV(xCipher.doFinal(keyBlock));

		Cipher sCipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
		sCipher.init(Cipher.DECRYPT_MODE, (Key)keyIv[0], (IvParameterSpec)keyIv[1]);

        byte[] random = sCipher.doFinal(cipheredRandom);

		return new byte[][]{random, keyBlock, cipheredRandom};
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

	private byte[] generateSecretSE(byte[] otherRandom) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		if(fromClassName.equals(HJSTREAMSERVER)) {
			out.write(random);
			out.flush();
			out.write(otherRandom);
			out.flush();
		}
		else {
			out.write(otherRandom);
			out.flush();
			out.write(random);
			out.flush();
		}

		MessageDigest md = MessageDigest.getInstance(SHA_ALGORITHM);
		return md.digest(out.toByteArray());
	}

	private byte[] generateCiphersuiteExtractMovieName(byte[] symmetricAndHmacKey, String[] cipherMode, int mode1, int mode2, byte[] movieNameData) throws Exception {
		int keyLenght = transformFromBitsToBytes(Integer.parseInt(cipherMode[1]));
		System.out.println(keyLenght);
		byte[] symmetricKey = Arrays.copyOfRange(symmetricAndHmacKey,0, keyLenght);

		// iv is obtained from the hash of the secret
		// (in the real world it will exist multiple hashes appended with 'AAAAA', 'BBBBB', etc)
		MessageDigest md = MessageDigest.getInstance(SHA_ALGORITHM);
		byte[] ivHashed = md.digest(symmetricKey);

		String transformation = cipherMode[0];  // Ex: AES/CCM/NoPadding
		ciphersuite = Cipher.getInstance(transformation);
		String[] algorithm = transformation.split(DELIMITER_ADDRESS);

		if(algorithm[0].equals("CHACHA20")){
			// nao vai dar pela mesma razão do GCM o iv tem de mudar com cada encriptaçao - TODO
		}

		String modeCipher = algorithm[1];

		AlgorithmParameterSpec ivSpec = null;
		SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, cipherMode[0].split(DELIMITER_ADDRESS)[0]); // AES

		switch(modeCipher){
			case CCM_MODE:
				ivSpec = new IvParameterSpec(Arrays.copyOfRange(ivHashed,0,7));
				break;
			case GCM_MODE: // GCM não dá porque iv tem de ser diferente em cada encriptação - TODO
				byte[] iv = Arrays.copyOfRange(ivHashed,0,12);
				ivSpec = new GCMParameterSpec(keyLenght * 8, iv);
				break;
			case CTR_MODE:
				ivSpec = new IvParameterSpec(Arrays.copyOfRange(ivHashed,0,16));
				break;
		}

		ciphersuite.init(mode1, secretKeySpec, ivSpec);
		System.out.println(ciphersuite.getAlgorithm());

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
		return generateCiphersuiteExtractMovieName(symmetricAndHmacKey,  ciphersuiteRTSP.split(DELIMITER_CONFIG), Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE, movieNameData);
	}

	private byte[] getMovieNameDecrypted(byte[] movieNameEncrypted) throws Exception {
		return generateCiphersuiteExtractMovieName(symmetricAndHmacKey,  ciphersuiteRTSP.split(DELIMITER_CONFIG), Cipher.DECRYPT_MODE, Cipher.ENCRYPT_MODE, movieNameEncrypted);
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

