package util;

import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

public class UtilsDHManipulation {

	// ---------------------------------------------------
	// Auxiliary methods to get DH Parameters and Keypairs
	// ---------------------------------------------------

	// 16 - hexadecimal
	// 36 - string contains digits (0-9) and letters (a-z;A-Z)
	// Needs to be a number from 2-36
	public static final int RADIX_INTEGER = 16;

	public static DHParameterSpec generateDHParameters(String diffieHellman, String keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException {
		AlgorithmParameterGenerator paramsGenerator = AlgorithmParameterGenerator.getInstance(diffieHellman, "BC");
		paramsGenerator.init(Integer.parseInt(keySize));
		AlgorithmParameters params = paramsGenerator.generateParameters();
		return (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
	}

	public static KeyPair generateDHKeys(String diffieHellman, DHParameterSpec specs) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(diffieHellman, "BC");
		keyGen.initialize(specs);
		return keyGen.generateKeyPair();
	}
}
