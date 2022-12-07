
package util;

import javax.crypto.spec.DHParameterSpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidParameterSpecException;

public class Utils {
	private static String	digits = "0123456789abcdef";
	public static final String PATH_TO_KEYSTORE = "src/main/java/certificates/"; //TODO mudei para testar com chain certificates
	public static final String PATH_TO_BOX_CONFIG = "src/main/java/hjBox/box-cryptoconfig.txt";
	public static final String PATH_TO_SERVER_CONFIG = "src/main/java/hjStreamServer/stream-cryptoconfig.txt";
	public static final String CIPHERSUITE_CONFIG_FILE = "src/main/java/crypto/ciphersuites.properties";
	public static final String PRESHARED_CONFIG_FILE = "src/main/java/crypto/preSharedHMAC.properties";
	public static final String HS_CONFIG_FILE = "src/main/java/crypto/handshake.properties";

	public static String toHex(byte[] data, int length) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i != length; i++) {
			int	v = data[i] & 0xff;

			buf.append(digits.charAt(v >> 4));
			buf.append(digits.charAt(v & 0xf));
		}
		return buf.toString();
	}

	public static String toHex(byte[] data) {
		return toHex(data, data.length);
	}

	public static DHParameterSpec generateDHParameters() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException {
		AlgorithmParameterGenerator paramsGenerator = AlgorithmParameterGenerator.getInstance("DH", "BC");
		paramsGenerator.init(2048);
		AlgorithmParameters params = paramsGenerator.generateParameters();
		return (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
	}

	public static KeyPair generateDHKeys(String diffieHellman, DHParameterSpec specs) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(diffieHellman, "BC");
		keyGen.initialize(specs);
		return keyGen.generateKeyPair();
	}

	public static Certificate retrieveCertificateFromKeystore(String keystoreName, String password, String aliasEntry) throws Exception {
		FileInputStream is = new FileInputStream(keystoreName+aliasEntry+".keystore");

		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, password.toCharArray());

		Key key = keystore.getKey("boxkeys", password.toCharArray());
		if (key instanceof PrivateKey) {
			return keystore.getCertificate("boxkeys");
		}
		throw new Exception("unable to retrieve certificate from keystore!");
	}

	public static PrivateKey retrievePrivateKeyFromKeystore(String keystoreName, String password, String aliasEntry) throws Exception { // TODO
		FileInputStream is = new FileInputStream(PATH_TO_KEYSTORE+keystoreName);

		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, password.toCharArray());

		Key key = keystore.getKey(aliasEntry, password.toCharArray());
		if (key instanceof PrivateKey) {
			return (PrivateKey) key;
		}
		throw new Exception("unable to retrieve certificate from keystore!");
	}
}


