package keystore;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.Base64;

public class KeyStoreGetKey {

	public static void main(String[] args) throws Exception {
		if(args.length != 5) {
			// streamstore.jks   12345omsqptaesd54321fommptvsnf12345iocmlesrfoqppms   RC6    rc6key   12345omsqptaesd54321fommptvsnf12345iocmlesrfoqppms
			System.out.println("Erro, usar: <fileKeyStore> <password> <algorithm> <secKey> <secPw>");
			System.exit(-1);
		}
		String fileKeyStore, pw, algorithm, secKey, secPw;
		fileKeyStore = args[0];
		pw = args[1];
		algorithm = args[2];
		secKey = args[3];
		secPw = args[4];

		KeyStore keyStore = KeyStoreCreation.createKeyStore(fileKeyStore, pw);

		// generate a secret key for AES encryption
		SecretKey secretKey = KeyGenerator.getInstance(algorithm).generateKey();
		System.out.println("Stored Key: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

		// store the secret key
		KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(secretKey);
		KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(secPw.toCharArray());
		keyStore.setEntry(secKey, keyStoreEntry, keyPassword);

		keyStore.store(new FileOutputStream(fileKeyStore), pw.toCharArray());

		// retrieve the stored key back
		KeyStore.Entry entry = keyStore.getEntry(secKey, keyPassword);
		SecretKey keyFound = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
		System.out.println("Found Key: " + Base64.getEncoder().encodeToString(keyFound.getEncoded()));
	}
}
