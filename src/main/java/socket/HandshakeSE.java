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
	public void createBoxHandshake() throws Exception {

	}

	@Override
	public void createServerHandshake() throws Exception {

	}
}
