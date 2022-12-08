package keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class KeyStoreCreation {

	private static final String JCEKS = "JCEKS";
	public static KeyStore createKeyStore(String fileName, String pw) throws Exception {
		File file = new File(fileName);

		final KeyStore keyStore = KeyStore.getInstance(JCEKS);
		if (file.exists()) {
			// .keystore file already exists => load it
			keyStore.load(new FileInputStream(file), pw.toCharArray());
		} else {
			// .keystore file not created yet => create it
			keyStore.load(null, null);
			keyStore.store(new FileOutputStream(fileName), pw.toCharArray());
		}
		return keyStore;
	}

	public static PublicKey readPublicKeyFromKeystore(String fileName, String pw, String secKey, String secPw) throws Exception {
		FileInputStream is = new FileInputStream(fileName);

		KeyStore keystore = KeyStore.getInstance(JCEKS);
		keystore.load(is, pw.toCharArray());

		Key key = keystore.getKey(secKey, secPw.toCharArray());
		if (key instanceof PrivateKey) {

			Certificate cert = keystore.getCertificate(secKey);
			return cert.getPublicKey();
		}
		return null;
	}

	public static PrivateKey readPrivateKeyFromKeystore(String fileName, String pw, String secKey, String secPw) throws Exception {
		FileInputStream is = new FileInputStream(fileName);

		KeyStore keystore = KeyStore.getInstance(JCEKS);
		keystore.load(is, pw.toCharArray());

		Key key = keystore.getKey(secKey, secPw.toCharArray());
		if (key instanceof PrivateKey) {
			return (PrivateKey) key;
		}
		return null;
	}
}
