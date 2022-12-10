package socket;

import javax.crypto.Cipher;
import javax.crypto.Mac;

public interface Handshake {


	Cipher getCipher();

	Mac getHMac();

	String getMovieName();

	void createBoxHandshake(String movieName) throws Exception;

	void createServerHandshake() throws Exception;

}
