package hjStreamServer;

/* hjStreamServer.java
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import crypto.DecryptMovie;
import socket.SafeDatagramSocket;
import java.io.DataInputStream;
import java.net.*;
import java.nio.charset.StandardCharsets;

public class hjStreamServer {

	static public void main( String []args ) throws Exception {
		if (args.length != 5) {
			   /*
				0	src/main/java/hjStreamServer/movies/cars.dat.encrypted
				1	src/main/java/hjStreamServer/movies-cryptoconfig.txt.encrypted
				2	236.16.20.30
				3	9999
				4	omsqptaesdfommptvsnfiocmlesrfoqppms
				*/
				System.out.println("Erro, usar: mySend <movie> <movies-config> <ip-multicast-address> <port> <box-config> <password>");
	           	System.out.println("        or: mySend <movie> <movies-config> <ip-unicast-address> <port> <box-config> <password>");
	           	System.exit(-1);
		}

		int size, count = -1;
		long time;
		byte[] buff = new byte[4 * 1024];

		SocketAddress addr = new InetSocketAddress(args[2], Integer.parseInt(args[3])); 		// <ip-multicast-address> <port>
		SafeDatagramSocket s = new SafeDatagramSocket(hjStreamServer.class.getSimpleName(), "password", addr);
		DataInputStream g = s.decryptMovie(args[1], args[4]);     // <movies-config> <password>

		DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
		long t0 = System.nanoTime(), q0 = 0, afs = 0;

		while ( g.available() > 0 ) {
			if(count == -1) { s.send(new DatagramPacket(args[0].getBytes(StandardCharsets.UTF_8), args[0].getBytes(StandardCharsets.UTF_8).length, addr)); count++; continue; }
			size = g.readShort();
			time = g.readLong();
			if ( count == 0 ) q0 = time;
			count += 1;
			g.readFully(buff, 0, size);
			p.setData(buff);
			p.setSocketAddress( addr );
			p = s.encrypt(p);
			afs += p.getLength();

			long t = System.nanoTime();
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );

			// send packet (with a frame payload)
			s.send(p);
			System.out.println("+");
		}
		s.printServerConfigStatus(args[0], count, afs, (double)(System.nanoTime()-t0)/1000000000);
		s.send(new DatagramPacket(SafeDatagramSocket.CONTROL_MESSAGE, SafeDatagramSocket.CONTROL_MESSAGE.length, addr));
	}

}
