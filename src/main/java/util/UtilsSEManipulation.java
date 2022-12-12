package util;

import java.security.*;

public class UtilsSEManipulation {

	// ---------------------------------
	// Auxiliary methods to get keyPairs
	// ---------------------------------

	public static PrivateKey generateSERandom(String mode, String keySize) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance(mode, "BC");
		generator.initialize(Integer.parseInt(keySize));
		return generator.generateKeyPair().getPrivate();
	}


}
