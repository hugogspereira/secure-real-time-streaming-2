package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import util.ConfigReader;
import util.CryptoStuff;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Properties;

/**
 * This class purpose is to encrypt movies so we can check later if we are doing
 * right the project
 */
public class EncryptMovie {

	private static final String CIPHERSUITE = "CIPHERSUITE";
	private static final String KEY = "KEY";
	private static final String IV = "IV";
	private static final String INTEGRITY = "INTEGRITY";
	private static final String MACKEY = "MACKEY";

	public static void main(String[] args) {
		if (args.length != 3) {
			System.out.println("Erro, usar: EncryptMovies <movie> <movies-config> <password>");
			System.exit(-1);
		}
		try {
			readProperties(args[0], args[1], args[2]);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void readProperties(String fullMovieName, String moviesConfig, String password) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		try {
			String[] path = fullMovieName.split("/");
			String movieName = path[path.length - 1];

			InputStream inputStream = new ByteArrayInputStream(
					ConfigReader.readMovie(moviesConfig, movieName, password).toByteArray());
			if (inputStream == null) {
				System.err.println("Configuration Movie file not found!");
				System.exit(1);
			}
			Properties properties = new Properties();
			properties.load(inputStream);

			String[] fullPath = fullMovieName.split(".encrypted");
			File inputFile = new File(fullPath[0]);
			inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int) inputFile.length()];
			inputStream.read(inputBytes);

			String encryptedfile = fullMovieName;
			File encryptedFile = new File(encryptedfile);

			int size = inputBytes.length;

			byte[] cipherText = CryptoStuff.encrypt(inputBytes, size, properties);

			FileOutputStream outputStream = new FileOutputStream(encryptedFile);
			outputStream.write(cipherText);

			inputStream.close();
			outputStream.close();

		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.getMessage());
		}
	}

	private static String checkProperty(Properties properties, String property) {
		String res = properties.getProperty(property);
		if (res.equalsIgnoreCase("NULL")) {
			res = null;
		}
		return res;
	}

}
