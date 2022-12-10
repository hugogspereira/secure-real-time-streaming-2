package util;

import java.net.SocketAddress;

public class Utils {

	public static final String PATH_TO_KEYSTORE = "src/main/java/certificates/";
	public static final String PATH_TO_BOX_CONFIG = "src/main/java/hjBox/box-cryptoconfig.txt";
	public static final String PATH_TO_SERVER_CONFIG = "src/main/java/hjStreamServer/stream-cryptoconfig.txt";
	public static final String CIPHERSUITE_CONFIG_FILE = "src/main/java/crypto/ciphersuites.properties";
	public static final String PRESHARED_CONFIG_FILE = "src/main/java/crypto/preSharedHMAC.properties";
	public static final String HS_CONFIG_FILE = "src/main/java/crypto/handshake.properties";
	public static final String SERVER_CONFIG_FILE = "src/main/java/hjStreamServer/config.properties";

	public static final String DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE";
	public static final String DIFFIE_HELLMAN = "DIFFIE_HELLMAN";
	public static final String SECURE_ENVELOPE = "SECURE_ENVELOPE";
	public static final String HJSTREAMSERVER = "hjStreamServer";

	public static final String DELIMITER_ADDRESS = "/";
	public static final String DELIMITER_PORT = ":";
	public static final String DELIMITER_PORT_CONFIG = "-";


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
		return (val/Byte.SIZE);
	}

}


