package util;

import java.net.DatagramSocket;

public class RTSSHandshake {

	private static RTSSHandshake instance;

	public RTSSHandshake() { // TODO

	}

	public static RTSSHandshake getInstance() {
		if(instance == null) {
			instance = new RTSSHandshake();
		}
		return instance;
	}


	public void handshakeBox(DatagramSocket inSocket, String boxConfig) {

	}
}
