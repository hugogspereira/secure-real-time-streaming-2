package socket;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.net.DatagramSocket;

public interface Handshake {


	Cipher getCipher();

	Mac getHMac();

	void createBoxHandshake(DatagramSocket inSocket) throws Exception;

	void createServerHandshake(DatagramSocket inSocket) throws Exception;



}
