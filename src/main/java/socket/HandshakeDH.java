package socket;

import util.ConfigReader;
import util.CryptoStuff;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import crypto.PBEFileDecryption;
import util.PrintStats;
import java.io.*;
import java.math.BigInteger;
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
import static util.UtilsObjectManipulation.*;
import static util.UtilsCertificateManipulation.*;
import static util.UtilsDHManipulation.*;

public class HandshakeDH implements Handshake {

	private final SocketAddress addr, addrToSend;
	private final OutputStream out;
	private final InputStream in;
	private final String fromClassName, certPassword;  // name to retrieve the certificate and the password
	private String movieName;
	// ---------------------------------------------
	private final String digitalSignature, diffieHellman;
	private KeyPair keysDH;
	private String ciphersuiteRTSP; // for the HS
	private Mac hMacHS; // for the HS
	// ---------------------------------------------
	private Cipher ciphersuite; // for the symmetric encryption
	private byte[] symmetricAndHmacKey; // data for the ciphersuite
	private Mac hMac; // for the symmetric encryption
	//----------------------------------------------
	private final String configPass; //password for config files
	private double timeHS;


	public HandshakeDH(Socket socket, String digitalSignature, String diffieHellman, String className, String certPassword, SocketAddress addr, SocketAddress addrToSend, String configPass) throws Exception {
		this.digitalSignature = digitalSignature;
		this.diffieHellman = diffieHellman;
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

	@Override
	public void printBoxConfigStatus(int count, long afs, double totalTime) {
		byte[] key = Arrays.copyOfRange(symmetricAndHmacKey,0, transformFromBitsToBytes(Integer.parseInt(ciphersuiteRTSP.split(DELIMITER_CONFIG)[1])));
		String[] movie = movieName.split(DELIMITER_ADDRESS);
		String moviename = movie[movie.length-1].split(".encrypted")[0];
		PrintStats.toPrintBoxConfigStats(moviename, ciphersuite.getAlgorithm(), Base64.getEncoder().encodeToString(key), key.length*Byte.SIZE, HMAC_ALGORITHM);
		PrintStats.toPrintBoxStats(count, (double)afs/count, afs, totalTime, (double)count/totalTime, (double)afs*1000/totalTime, timeHS);
	}

	@Override
	public void printServerConfigStatus(int count, long afs, double totalTime) {
		byte[] key = Arrays.copyOfRange(symmetricAndHmacKey,0, transformFromBitsToBytes(Integer.parseInt(ciphersuiteRTSP.split(DELIMITER_CONFIG)[1])));
		String[] movie = movieName.split(DELIMITER_ADDRESS);
		String moviename = movie[movie.length-1].split(".encrypted")[0];
		PrintStats.toPrintServerConfigStats(moviename, ciphersuite.getAlgorithm(), Base64.getEncoder().encodeToString(key), key.length*Byte.SIZE, HMAC_ALGORITHM);
		PrintStats.toPrintServerStats(count, (double)afs/count, afs, totalTime, (double)count/totalTime, (double)afs*1000/totalTime, timeHS);
	}



	public void createBoxHandshake(String movieName) throws Exception {
		this.movieName = movieName;
		long time0 = System.nanoTime();
		sendFirstMessageHS();
		receiveSecondMessageHS();
		sendThirdMessageHS(movieName);
		timeHS = (double)(System.nanoTime()-time0)/1000000000;
	}

	public void createServerHandshake() throws Exception {
		// Waits until the box sends the message
		waitForTheSend();
		long time0 = System.nanoTime();

		receiveFirstMessageHS();
		sendSecondMessageHS();
		this.movieName = receiveThirdMessageHS();
		timeHS = (double)(System.nanoTime()-time0)/1000000000;
	}

	private void sendFirstMessageHS() throws Exception {
		//System.out.println("Vou enviar 1a msg");

		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		// Read the ciphersuites available for box
		writeCiphersuitesAvailableBox(oos);

		// Certificate
		writeCertificate(oos);

		// DH Parameters Generation
		String[] dhs = diffieHellman.split(DELIMITER_CONFIG);
		String dh = dhs[0];
		String dhKeySize = dhs[1];

		Properties properties = new Properties();
		properties.load(new FileInputStream(HS_DH_CONFIG_FILE));

		boolean dynamicGenerationOfDHParameters = Boolean.parseBoolean(checkProperty(properties, DYNAMIC_DH_PARAMETERS));
		DHParameterSpec dhParams;
		BigInteger p, g;

		if(dynamicGenerationOfDHParameters) {
			dhParams = generateDHParameters(dh, dhKeySize);

			p = dhParams.getP();
			g = dhParams.getG();
		}
		else {
			String pString = checkProperty(properties, "P_"+dhKeySize);
			String gString = checkProperty(properties, "G_"+dhKeySize);

			p = new BigInteger(pString, RADIX_INTEGER);
			g = new BigInteger(gString, RADIX_INTEGER);

			dhParams = new DHParameterSpec(p,g);
		}
		keysDH = generateDHKeys(dh, dhParams);

		// PublicNum Box
		PublicKey publicKeyDH = keysDH.getPublic();

		// Write the Dh Parameters
		writeDHParametersBox(oos, publicKeyDH, p, g);

		// Create the message that box will sign
		byte[] message2 = getMessageToSignBoxDH(publicKeyDH, p, g);
		// Signature
		writeDigitalSignature(oos, message2);

		byte[] messageTotal = bos.toByteArray();
		// HMAC
		writeHMacHS(oos, messageTotal);

		byte[] data = bos.toByteArray();
		out.write(data);

		//System.out.println("Enviei 1a msg");
		//System.out.println("---------------------");
	}

	private void receiveFirstMessageHS() throws Exception {
		//System.out.println("Vou receber 1a msg");
		DataInputStream inputStream = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(inputStream);

		// lista de ciphersuites
		int ciphersuiteLength = ois.readInt();
		String[] boxCiphersuites = new String[ciphersuiteLength];
		for(int i = 0; i < ciphersuiteLength; i++) {
			boxCiphersuites[i] = ois.readUTF();
		}
		Properties ciphersuitesProperties = new Properties();
		ciphersuitesProperties.load(new FileInputStream(CIPHERSUITE_CONFIG_FILE));
		ciphersuiteRTSP = ciphersuitesProperties.getProperty(chooseCommonCipher(boxCiphersuites, ConfigReader.readCiphersuites(PATH_TO_SERVER_CONFIG, addrToSend.toString().split(DELIMITER_ADDRESS)[1])));

		// Certificate
		X509Certificate cert = (X509Certificate) ois.readObject();
		validateCertificate(cert);

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
		Signature sig = Signature.getInstance(digitalSignature.split(DELIMITER_CONFIG)[0],"BC");
		sig.initVerify(publicKeyBox);
		if(sig.verify(signedBytes)) {
			throw new Exception("Invalid signature!   != Sig_kprivServer(Yserver || P || G)");
		}

		// Generate the bytes
		byte[] messageTotal = getBytesOfFirstMessageDH(ciphersuiteLength,boxCiphersuites,cert,boxPubKey,p,g,signatureLength,signedBytes);

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
		// Generate the secret - from where it will be extracted the symetric key and the HMAC key
		symmetricAndHmacKey = generateSecretDHServer(p,g,boxPubKey);
		// Parte que vai para a chave HMAC
		generateHMacKey(symmetricAndHmacKey, cipherMode);

		//System.out.println("Recebi 1a msg");
		//System.out.println("---------------------");
	}


	private void sendSecondMessageHS() throws Exception {
		//System.out.println("Vou enviar 2a msg");
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
		writeHMacHS(oos, messageTotal);

		byte[] data = bos.toByteArray();
		out.write(data);

		//System.out.println("Enviei 2a msg");
		//System.out.println("---------------------");
	}

	private void receiveSecondMessageHS() throws Exception {
		//System.out.println("Vou receber 2 msg");
		DataInputStream inputStream = new DataInputStream(in);
		ObjectInputStream ois = new ObjectInputStream(inputStream);

		waitForTheSend();

		// Ciphersuite escolhida
		String cs = ois.readUTF();
		ciphersuiteRTSP = cs;

		// certificate
		X509Certificate cert = (X509Certificate) ois.readObject();
		validateCertificate(cert);

		PublicKey publicKeyServer = cert.getPublicKey();

		// Yserver
		PublicKey serverPubKey = (PublicKey) ois.readObject();

		// Signature
		int signatureLength = ois.readInt();
		// Byte Arrays that will be compared to see if its everything fine
		byte[] signedBytes = ois.readNBytes(signatureLength);

		Signature sig = Signature.getInstance(digitalSignature.split(DELIMITER_CONFIG)[0],"BC");
		sig.initVerify(publicKeyServer);
		if(sig.verify(signedBytes)) {
			throw new Exception("Invalid signature!   != Sig_kprivServer(Yserver || P || G)");
		}

		// Generate the bytes
		byte[] messageTotal = getBytesOfSecondMessageDH(cs,cert,serverPubKey,signatureLength,signedBytes);

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
		// Generate the secret - from where it will be extracted the symetric key and the HMAC key
		symmetricAndHmacKey = generateSecretDH(serverPubKey);
		// Parte que vai para a chave HMAC
		generateHMacKey(symmetricAndHmacKey, cipherMode);
		//System.out.println("Recebi 2a msg");
		//System.out.println("---------------------");
	}

	private void sendThirdMessageHS(String movieName) throws Exception {
		//System.out.println("Vou enviar 3a msg");
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
		//System.out.println("Enviei 3a msg");
		//System.out.println("---------------------");
	}

	private String receiveThirdMessageHS()  throws Exception {
		//System.out.println("Vou receber 3a msg");
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

		//System.out.println("Recebi 3a msg");
		//System.out.println("---------------------");
		return new String(movieNameData);
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

	private byte[] generateSecretDHServer(BigInteger p, BigInteger g, PublicKey pubKey) throws Exception {
		DHParameterSpec dhParams = new DHParameterSpec(p, g);
		keysDH = generateDHKeys(getAlgorithmFromConfigString(diffieHellman), dhParams);

		return generateSecretDH(pubKey);
	}

	private byte[] generateSecretDH(PublicKey pubKey) throws Exception {
		KeyAgreement keyAgree = KeyAgreement.getInstance(getAlgorithmFromConfigString(diffieHellman), "BC");
		keyAgree.init(keysDH.getPrivate());
		keyAgree.doPhase(pubKey, true);
		byte[] secretKey = keyAgree.generateSecret();

		MessageDigest md = MessageDigest.getInstance(SHA_ALGORITHM);
		return md.digest(secretKey);
	}

	private byte[] generateCiphersuiteExtractMovieName(byte[] symmetricAndHmacKey, String[] cipherMode, int mode1, int mode2, byte[] movieNameData) throws Exception {
		int keyLenght = transformFromBitsToBytes(Integer.parseInt(cipherMode[1]));
		byte[] symmetricKey = Arrays.copyOfRange(symmetricAndHmacKey,0, keyLenght);

		// iv is obtained from the hash of the secret
		// (in the real world it will exist multiple hashes appended with 'AAAAA', 'BBBBB', etc)
		MessageDigest md = MessageDigest.getInstance(SHA_ALGORITHM);
		byte[] ivHashed = md.digest(symmetricKey);

		String transformation = cipherMode[0];  // Ex: AES/CCM/NoPadding
		ciphersuite = Cipher.getInstance(transformation);
		String[] algorithm = transformation.split(DELIMITER_ADDRESS);
		String modeCipher = algorithm[1];

		AlgorithmParameterSpec ivSpec = null;
		SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, cipherMode[0].split(DELIMITER_ADDRESS)[0]); // AES

		switch(modeCipher){
			case CCM_MODE:
				ivSpec = new IvParameterSpec(Arrays.copyOfRange(ivHashed,0,7));
				break;
			case CTR_MODE:
				ivSpec = new IvParameterSpec(Arrays.copyOfRange(ivHashed,0,16));
				break;
		}

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
		//System.out.println("*** recebi pacote - vou avançar ***");
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
