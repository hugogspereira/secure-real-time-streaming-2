package socket;

import javax.crypto.Cipher;
import javax.crypto.Mac;

public class HandshakeSE implements Handshake {

	@Override
	public Cipher getCipher() {
		return null;
	}

	@Override
	public Mac getHMac() {
		return null;
	}

	@Override
	public String getMovieName() {
		return null;
	}

	@Override
	public void createBoxHandshake(String movieName) throws Exception {

	}

	@Override
	public void createServerHandshake() throws Exception {

	}
}
