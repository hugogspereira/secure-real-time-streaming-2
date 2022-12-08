package socket;

import javax.crypto.Cipher;
import javax.crypto.Mac;

public interface Handshake {


	Cipher getCipher();

	Mac getHMac();

	void createBoxHandshake() throws Exception;

	void createServerHandshake() throws Exception;



}
