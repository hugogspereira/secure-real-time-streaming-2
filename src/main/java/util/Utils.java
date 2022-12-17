package util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.SocketAddress;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Utils {

	public static final String PATH_TO_KEYSTORE = "src/main/java/certificates/";
	public static final String PATH_TO_BOX_CONFIG = "src/main/java/hjBox/box-cryptoconfig.txt"; // does not need to be
																								// encrypted
	public static final String PATH_TO_SERVER_CONFIG = "src/main/java/hjStreamServer/stream-cryptoconfig.txt"; // does
																												// not
																												// need
																												// to be
																												// encrypted
	public static final String CIPHERSUITE_CONFIG_FILE = "src/main/java/crypto/ciphersuites.properties"; // does not
																											// need to
																											// be
																											// encrypted
	public static final String HS_CONFIG_FILE = "src/main/java/crypto/handshake.properties"; // does not need to be
																								// encrypted
	public static final String PRESHARED_CONFIG_FILE = "src/main/java/crypto/preSharedHMAC.properties.encrypted";
	public static final String SERVER_CONFIG_FILE = "src/main/java/hjStreamServer/config.properties.encrypted";

	public static final String DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE";
	public static final String DIFFIE_HELLMAN = "DIFFIE_HELLMAN";
	public static final String SECURE_ENVELOPE = "SECURE_ENVELOPE";
	public static final String HJSTREAMSERVER = "hjStreamServer";

	public static final String DELIMITER_ADDRESS = "/";
	public static final String DELIMITER_CONFIG = "-";
	public static final String DELIMITER_PORT = ":";
	public static final String DELIMITER_PORT_CONFIG = "-";

	public static final String CCM_MODE = "CCM";
	public static final String GCM_MODE = "GCM";
	public static final String CTR_MODE = "CTR";

	public static final String HMAC_ALGORITHM = "HmacSHA256";
	public static final String SHA_ALGORITHM = "SHA-512";

	public static String removeSlashFromAddress(SocketAddress addr) {
		return removeSlashFromString(addr.toString());
	}

	public static String removeSlashFromString(String property) {
		return property.split(DELIMITER_ADDRESS)[1];
	}

	public static String getPropertyNameFromAddress(SocketAddress addr) {
		return removeSlashFromAddress(addr).replace(DELIMITER_PORT, DELIMITER_PORT_CONFIG);
	}

	public static String getAlgorithmFromConfigString(String property) {
		return property.split(DELIMITER_PORT_CONFIG)[0];
	}

	public static String getKeySizeFromConfigString(String property) {
		return property.split(DELIMITER_PORT_CONFIG)[1];
	}

	public static int transformFromBitsToBytes(int val) {
		return (val / Byte.SIZE);
	}

	public static SecretKey createKeyForAES(int bitLength, SecureRandom random)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");

		generator.init(256, random);

		return generator.generateKey();
	}

	public static byte[] packKeyAndIv(Key key, IvParameterSpec ivSpec) throws IOException {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		bOut.write(ivSpec.getIV());
		bOut.write(key.getEncoded());

		return bOut.toByteArray();
	}

	public static Object[] unpackKeyAndIV(byte[] data) {	
		return new Object[] {
				new SecretKeySpec(data, 16, data.length - 16, "AES"),
				new IvParameterSpec(data, 0, 16)
		};
	}

}
