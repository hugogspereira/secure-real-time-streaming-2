package util;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class UtilsCertificateManipulation {


	// ------------------------------------------------------------------
	// Auxiliary methods to get Certificates and Private Key of KeyStores
	// ------------------------------------------------------------------

	public static Certificate retrieveCertificateFromKeystore(String keystoreName, String password, String aliasEntry) throws Exception {
		FileInputStream is = new FileInputStream(keystoreName+aliasEntry+".keystore");

		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, password.toCharArray());

		Key key = keystore.getKey(aliasEntry.toLowerCase(), password.toCharArray());
		if (key instanceof PrivateKey) {
			return keystore.getCertificate(aliasEntry.toLowerCase());
		}
		throw new Exception("unable to retrieve certificate from keystore!");
	}

	public static Certificate retrieveCACertificate(String keystoreName, String password, String aliasEntry)throws Exception {
		FileInputStream is = new FileInputStream(keystoreName+aliasEntry+".keystore");

		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, password.toCharArray());

		Certificate crt = keystore.getCertificate("ca");

		if(crt != null){
			return crt;
		}
		throw new Exception("unable to retrieve certificate from keystore!");
	}

	public static PrivateKey retrievePrivateKeyFromKeystore(String keystoreName, String password, String aliasEntry) throws Exception {
		FileInputStream is = new FileInputStream(keystoreName+aliasEntry+".keystore");

		KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, password.toCharArray());

		Key key = keystore.getKey(aliasEntry.toLowerCase(), password.toCharArray());
		if (key instanceof PrivateKey) {
			return (PrivateKey) key;
		}
		throw new Exception("unable to retrieve certificate from keystore!");
	}
}
