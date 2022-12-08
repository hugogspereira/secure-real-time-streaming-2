package socket;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.net.DatagramSocket;

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
	public void createBoxHandshake(DatagramSocket inSocket) throws Exception {

	}

	@Override
	public void createServerHandshake(DatagramSocket inSocket) throws Exception {

	}
}
