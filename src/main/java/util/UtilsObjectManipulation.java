package util;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class UtilsObjectManipulation {


	// -----------------------------------------------------------------------------------------
	// Auxiliary methods to get bytes of the message for the HMAC comparation in the DH Protocol
	// -----------------------------------------------------------------------------------------

	public static byte[] getBytesOfFirstMessageDH(int ciphersuiteLength, String[] boxCiphersuites, X509Certificate cert,
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

	public static byte[] getBytesOfFirstMessageSE(X509Certificate cert, int ciphersuitesLength, String[] boxCiphersuites) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		oos.writeObject(cert);
		oos.flush();

		oos.writeInt(ciphersuitesLength);
		oos.flush();
		// Array of ciphersuites
		for (String cipherString: boxCiphersuites) {
			oos.writeUTF(cipherString);
			oos.flush();
		}

		return bos.toByteArray();
	}

	public static byte[] getBytesOfSecondMessageDH(String cs, X509Certificate cert, PublicKey serverPubKey, int signatureLength, byte[] signedBytes) throws Exception {
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

	public static byte[] getBytesOfSecondMessageSE(X509Certificate cert, String ciphersuiteRTSP, int cipherLen, byte[] cipheredRandom, int signatureLength, byte[] signedBytes) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		oos.writeObject(cert);
		oos.flush();

		oos.writeUTF(ciphersuiteRTSP);
		oos.flush();

		oos.writeInt(cipherLen);
		oos.flush();
		oos.write(cipheredRandom);
		oos.flush();
		oos.writeInt(signatureLength);
		oos.flush();
		oos.write(signedBytes);
		oos.flush();

		return bos.toByteArray();
	}

	public static byte[] getBytesOfThirdMessageSE(int cipheredRandomLen, byte[] cipheredRandom, int signatureLength, byte[] signedBytes, int movieLength, byte[] movieNameEncrypted) throws Exception {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bos);

		oos.writeInt(cipheredRandomLen);
		oos.flush();
		oos.write(cipheredRandom);
		oos.flush();
		oos.writeInt(signatureLength);
		oos.flush();
		oos.write(signedBytes);
		oos.flush();
		oos.writeInt(movieLength);
		oos.flush();
		oos.write(movieNameEncrypted);
		oos.flush();

		return bos.toByteArray();
	}

	public static byte[] getBytesOfPublicKey(PublicKey pubKey) throws Exception {
		ByteArrayOutputStream auxBos = new ByteArrayOutputStream();
		ObjectOutputStream auxOos = new ObjectOutputStream(auxBos);

		auxOos.writeObject(pubKey);
		auxOos.flush();

		return auxBos.toByteArray();
	}

	public static byte[] getMessageToSignBoxDH(PublicKey publicKeyDH, BigInteger p, BigInteger g) throws Exception {
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

}
