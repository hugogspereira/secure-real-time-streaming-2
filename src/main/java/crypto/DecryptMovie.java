package crypto;

import util.ConfigReader;
import util.CryptoStuff;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Properties;

public class DecryptMovie {

	private static final String CIPHERSUITE = "CIPHERSUITE";
	private static final String KEY = "KEY";
	private static final String IV = "IV";
	private static final String INTEGRITY = "INTEGRITY";
	private static final String MACKEY = "MACKEY";

	private InputStream dataInputStream;
	Properties properties;

	public DecryptMovie(String movieName, String moviesConfig, String password) throws Exception {
		byte[] movieData;
		try {
			File inputFile = new File(movieName);
			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] data = new byte[(int) inputFile.length()];
			inputStream.read(data);

			String[] path = movieName.split("/");
			String movieNameAux = path[path.length - 1];

			InputStream inStream = new ByteArrayInputStream(ConfigReader.readMovie(moviesConfig, movieNameAux, password).toByteArray());
			if (inStream == null) {
				System.err.println("Configuration Movie file not found!");
				System.exit(1);
			}
			properties = new Properties();
			properties.load(inStream);

			movieData = CryptoStuff.decrypt(data, data.length, properties);

		} catch (NoSuchAlgorithmException e) {
			throw new IOException("Receive Encrypted data has failed! No such algorithm exception", e);
		} catch (NoSuchPaddingException e) {
			throw new IOException("Receive Encrypted data has failed! No such padding exception", e);
		} catch (InvalidKeyException e) {
			throw new IOException("Receive Encrypted data has failed! Invalid key exception", e);
		} catch (BadPaddingException e) {
			throw new IOException("Receive Encrypted data has failed! Bad padding exception", e);
		} catch (IllegalBlockSizeException e) {
			throw new IOException("Receive Encrypted data has failed! Illegal block size exception", e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IOException("Receive Encrypted data has failed! Invalid algorithm parameter exception", e);
		}
		this.dataInputStream = new ByteArrayInputStream(movieData);
	}

	public DataInputStream getDataInputStream() {
		if (dataInputStream == null) {
			System.out.println("Error occured during decryption of movie");
			System.exit(1);
		}
		return new DataInputStream(dataInputStream);
	}

}
