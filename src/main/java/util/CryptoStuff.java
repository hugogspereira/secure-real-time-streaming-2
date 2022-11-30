package util;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import java.security.*;
import java.util.Properties;
import java.io.IOException;

public class CryptoStuff {

    private static final String CIPHERSUITE = "CIPHERSUITE";
    private static final String KEY = "KEY";
    private static final String IV = "IV";
    private static final String INTEGRITY = "INTEGRITY";
    private static final String MACKEY = "MACKEY";

    public static byte[] encrypt(byte[] data, int size, Properties props) throws IOException {
        Security.addProvider(new BouncyCastlePQCProvider());

        String integrity = checkProperty(props, INTEGRITY);
        String mackey = checkProperty(props, MACKEY);
        String ciphersuite = checkProperty(props, CIPHERSUITE);
        String key = checkProperty(props, KEY);
        String iv = checkProperty(props, IV);

        int integritySize, ctLength;
        byte[] cipherText, integrityData;

        try {
            Cipher cipher = Cipher.getInstance(ciphersuite);
            if (ciphersuite == null) {
                throw new IOException("Ciphersuite is invalid");
            }
            String[] transformation = ciphersuite.split("/");
            String mode = null;
            if (transformation.length > 1) {
                mode = transformation[1];
            }
            if (iv == null) {
                throw new IOException("Iv is invalid");
            }
            if (mode != null && mode.equalsIgnoreCase("CCM")) {
                if (iv.getBytes().length < 7 || iv.getBytes().length > 13) {
                    throw new IOException("With CCM mode the iv should be between 7 and 13 bytes");
                } else if (mackey == null) {
                    throw new IOException("With CCM mode the mac is necessary");
                }
            }
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
            if (key == null) {
                throw new IOException("Key is invalid");
            }
            SecretKey secretKey = new SecretKeySpec(key.getBytes(), 0, key.getBytes().length,
                    ciphersuite.split("/")[0]);

            if (cipher.getAlgorithm().equals("ARCFOUR")) {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }
            else {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            }

            if (mode != null && mode.equalsIgnoreCase("GCM")
                    || transformation[0].equalsIgnoreCase("ChaCha20-Poly1305")) {
                return cipher.doFinal(data);
            }
            if (integrity != null) {
                if (mackey == null) {
                    MessageDigest hash = MessageDigest.getInstance(integrity);
                    integritySize = hash.getDigestLength();

                    cipherText = new byte[cipher.getOutputSize(size + integritySize)];
                    ctLength = cipher.update(data, 0, size, cipherText, 0);

                    hash.update(data);
                    integrityData = hash.digest();
                } else {
                    Mac hMac = Mac.getInstance(integrity);
                    Key hMacKey = new SecretKeySpec(checkProperty(props, KEY).getBytes(), mackey);
                    hMac.init(hMacKey);
                    integritySize = hMac.getMacLength();

                    cipherText = new byte[cipher.getOutputSize(size + integritySize)];
                    ctLength = cipher.update(data, 0, size, cipherText, 0);

                    hMac.update(data);
                    integrityData = hMac.doFinal();
                }
                cipher.doFinal(integrityData, 0, integritySize, cipherText, ctLength);
            }
            else return cipher.doFinal(data, 0, size);

        } catch (BadPaddingException e) {
            throw new IOException("Encrypt data has failed! Bad padding exception", e);
        } catch (IllegalBlockSizeException e) {
            throw new IOException("Encrypt data has failed! Illegal block size exception", e);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Encrypt data has failed! No such algorithm", e);
        } catch (ShortBufferException e) {
            throw new IOException("Encrypt data has failed! Short Buffer Exception", e);
        } catch (InvalidKeyException e) {
            throw new IOException("Encrypt data has failed! Invalid Mac key Exception", e);
        } catch (NoSuchPaddingException e) {
            throw new IOException("Send Encrypted data has failed! No such padding exception", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IOException("Send Encrypted data has failed! Invalid algorithm parameter exception", e);
        }

        return cipherText;
    }

    public static byte[] encrypt(byte[] data, int size, Cipher cipher, Mac hMac) throws IOException {
        int integritySize, ctLength;
        byte[] cipherText, integrityData;

        try {
            integritySize = hMac.getMacLength();

            cipherText = new byte[cipher.getOutputSize(size + integritySize)];
            ctLength = cipher.update(data, 0, size, cipherText, 0);

            hMac.update(data);
            integrityData = hMac.doFinal();
            cipher.doFinal(integrityData, 0, integritySize, cipherText, ctLength);
            return cipherText;
        } catch (BadPaddingException e) {
            throw new IOException("Encrypt data has failed! Bad padding exception", e);
        } catch (IllegalBlockSizeException e) {
            throw new IOException("Encrypt data has failed! Illegal block size exception", e);
        } catch (ShortBufferException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(byte[] data, int size, Properties props) throws IOException, IntegrityFailedException {
        Security.addProvider(new BouncyCastlePQCProvider());

        String integrity = checkProperty(props, INTEGRITY);
        String mackey = checkProperty(props, MACKEY);
        String ciphersuite = checkProperty(props, CIPHERSUITE);
        String key = checkProperty(props, KEY);
        String iv = checkProperty(props, IV);
        

        byte[] decryptedData, messageIntegrity, realData;
        int messageLength;

        try {
            Cipher cipher = Cipher.getInstance(ciphersuite);
            if (ciphersuite == null) {
                throw new IOException("Ciphersuite is invalid");
            }
            String[] transformation = ciphersuite.split("/");
            String mode = null;
            if (transformation.length > 1) {
                mode = transformation[1];
            }
            if (iv == null) {
                throw new IOException("Iv is invalid");
            }
            if (mode != null && mode.equalsIgnoreCase("CCM")) {
                if (iv.getBytes().length < 7 || iv.getBytes().length > 13) {
                    throw new IOException("With CCM mode the iv should be between 7 and 13 bytes");
                } else if (mackey == null) {
                    throw new IOException("With CCM mode the mac is necessary");
                }
            }
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
            if (key == null) {
                throw new IOException("Key is invalid");
            }
            SecretKey secretKey = new SecretKeySpec(key.getBytes(), 0, key.getBytes().length,
                    ciphersuite.split("/")[0]);
            if(cipher.getAlgorithm().equals("ARCFOUR")) {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            }
            else {
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            }
                
            if (mode != null && mode.equalsIgnoreCase("GCM")
                    || transformation[0].equalsIgnoreCase("ChaCha20-Poly1305")) {
                return cipher.doFinal(data, 0, size);
            }
            if (integrity != null) {
                if (mackey == null) {
                    MessageDigest hash = MessageDigest.getInstance(integrity);

                    decryptedData = cipher.doFinal(data, 0, size);
                    messageLength = decryptedData.length - hash.getDigestLength();
                    realData = new byte[messageLength];
                    hash.update(decryptedData, 0, messageLength);

                    messageIntegrity = new byte[hash.getDigestLength()];
                    System.arraycopy(decryptedData, messageLength, messageIntegrity, 0, messageIntegrity.length);

                    if (MessageDigest.isEqual(hash.digest(), messageIntegrity)) {
                        System.arraycopy(decryptedData, 0, realData, 0, messageLength);
                    } else { // Não mandar o packet! Integrity check failed!
                        throw new IntegrityFailedException("Invalid integrity! Integrity check failed!");
                    }
                } else {
                    Mac hMac = Mac.getInstance(integrity);
                    Key hMacKey = new SecretKeySpec(checkProperty(props, KEY).getBytes(), mackey);

                    decryptedData = cipher.doFinal(data, 0, size);
                    messageLength = decryptedData.length - hMac.getMacLength();
                    realData = new byte[messageLength];

                    hMac.init(hMacKey);
                    hMac.update(decryptedData, 0, messageLength);

                    messageIntegrity = new byte[hMac.getMacLength()];
                    System.arraycopy(decryptedData, messageLength, messageIntegrity, 0, messageIntegrity.length);

                    if (MessageDigest.isEqual(hMac.doFinal(), messageIntegrity)) {
                        System.arraycopy(decryptedData, 0, realData, 0, messageLength);
                    } else { // Não mandar o packet! Integrity check failed!
                        throw new IntegrityFailedException("Invalid integrity! Integrity check failed!");
                    }
                }
            } else
                realData = cipher.doFinal(data, 0, size);

            return realData;

        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Receive Encrypted data has failed! No such algorithm exception", e);
        } catch (InvalidKeyException e) {
            throw new IOException("Receive Encrypted data has failed! Invalid key exception", e);
        } catch (BadPaddingException e) {
            throw new IOException("Receive Encrypted data has failed! Bad padding exception", e);
        } catch (IllegalBlockSizeException e) {
            throw new IOException("Receive Encrypted data has failed! Illegal block size exception", e);
        } catch (NoSuchPaddingException e) {
            throw new IOException("Send Encrypted data has failed! No such padding exception", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IOException("Send Encrypted data has failed! Invalid algorithm parameter exception", e);
        }
    }

    public static byte[] decrypt(byte[] data, int size, Cipher cipher, Mac hMac) throws IOException, IntegrityFailedException {
        byte[] decryptedData, messageIntegrity, realData;
        int messageLength;

        try {
            decryptedData = cipher.doFinal(data, 0, size);
            messageLength = decryptedData.length - hMac.getMacLength();
            realData = new byte[messageLength];
            hMac.update(decryptedData, 0, messageLength);

            messageIntegrity = new byte[hMac.getMacLength()];
            System.arraycopy(decryptedData, messageLength, messageIntegrity, 0, messageIntegrity.length);

            if (MessageDigest.isEqual(hMac.doFinal(), messageIntegrity)) {
                System.arraycopy(decryptedData, 0, realData, 0, messageLength);
            } else {
                // Não mandar o packet! Integrity check failed!
                throw new IntegrityFailedException("Invalid integrity! Integrity check failed!");
            }
            return realData;

        } catch (BadPaddingException e) {
            throw new IOException("Receive Encrypted data has failed! Bad padding exception", e);
        } catch (IllegalBlockSizeException e) {
            throw new IOException("Receive Encrypted data has failed! Illegal block size exception", e);
        }
    }

    public static Cipher readProps(Properties props, int cipherMode) throws IOException {
        String ciphersuit = checkProperty(props, CIPHERSUITE);
        String key = checkProperty(props, KEY);
        String iv = checkProperty(props, IV);

        Security.addProvider(new BouncyCastlePQCProvider());

        try {
            if (ciphersuit == null) {
                throw new IOException("Ciphersuite is invalid");
            }
            Cipher cipher = Cipher.getInstance(ciphersuit);

            if (iv == null) {
                throw new IOException("Iv is invalid");
            }
            IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());

            if (key == null) {
                throw new IOException("Key is invalid");
            }
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ciphersuit.split("/")[0]);

            cipher.init(cipherMode, secretKey, ivSpec);
            return cipher;

        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Encript/Decript data has failed! No such algorithm exception", e);
        } catch (NoSuchPaddingException e) {
            throw new IOException("Encript/Decript data has failed! No such padding exception", e);
        } catch (InvalidKeyException e) {
            throw new IOException("Encript/Decript data has failed! Invalid key exception", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IOException("Encript/Decript data has failed! Invalid algorithm parameter exception", e);
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
