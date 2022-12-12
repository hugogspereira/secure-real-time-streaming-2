package util;

import java.security.*;

public class UtilsSEManipulation {

	// ---------------------------------
	// Auxiliary methods to get keyPairs
	// ---------------------------------

	public static byte[] generateSERandom(int bytes) throws Exception {
		return SecureRandom.getInstanceStrong().generateSeed(bytes);
	}


}
