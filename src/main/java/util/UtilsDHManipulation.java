package util;

import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

public class UtilsDHManipulation {

	// ------------------------------------------------------------------
	// Auxiliary methods to get Certificates and Private Key of KeyStores
	// ------------------------------------------------------------------

	public static DHParameterSpec generateDHParameters(String keySize) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidParameterSpecException {
		AlgorithmParameterGenerator paramsGenerator = AlgorithmParameterGenerator.getInstance("DH", "BC");
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
