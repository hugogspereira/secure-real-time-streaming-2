package hjBox;

/* hjBox, 22/23
 *
 * This is a very simple emulation of what we can call 
 * setup Box, to receice UDP-based network streams (for exampple
 * streaming sent from a StreamingServer (see the Streaming Server in
 * the provided materials). UDP streaming from the server can support
 * the dissemination of encoded movies, sent with encoded frames and 
 * sent by teh Streaming Server frame by frame in real time, 
 * for real-time visualization.
 * The emulated Box is able to receive and process the received streamed 
 * frames and can resend these frames in real time for user visualization.
 * The visualization can be done by any tool that can process and play
 * FFMPEG frames received as UDO network streams from the proxy. We
 * suggest the use of an open source tool, such as VLC for this purpose.
 *
 * The hjProxy working as a proxy between the StreamingServer and the 
 * visualization tool must be listening on a remote source (endpoint used by
 * the StreamingServer server) as UDP sender, and can transparently 
 * forward received datagram packets carrying movie frames in the
 * delivering endpoint where the visualizatuon tool (VLC) is expecting.
 *
 * hjBox has a configuration file, with the following setup info
 * See the file "config.properties"
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.io.InputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import socket.DatagramSocketCreator;
import socket.SafeDatagramSocket;
import crypto.PBEFileDecryption;

public class hjBox {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        InputStream inputStream = PBEFileDecryption.decryptFiles(args[1], args[0]); // <password>  <config>
        if (args.length != 4) {
            /*
            0    src/main/java/hjBox/config.properties.encrypted
            1    omsqptaesdfommptvsnfiocmlesrfoqppms
            2    236.16.20.31:9999                                  -> endereço do server
            3    src/main/java/hjStreamServer/movies/cars.dat.encrypted
		    */
            System.out.println("Erro, usar: myBox <config> <box-config> <password>");
            System.err.println("Configuration file not found!");
            System.exit(-1);
        }
        
        Properties properties = new Properties();
        properties.load(inputStream);
	    String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        InetSocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

        DatagramSocket inSocket = DatagramSocketCreator.create(inSocketAddress);
        SafeDatagramSocket outSocket = new SafeDatagramSocket(inSocket, hjBox.class.getSimpleName(), "password", inSocketAddress, args[2], args[3], args[1]);
      
        byte[] buffer = new byte[5 * 1024];
        DatagramPacket p, inPacket; int count = 0; long afs = 0, t0 = -1; String movieName = "";
        while (true) {
            inPacket = new DatagramPacket(buffer, buffer.length);
 	        inSocket.receive(inPacket);  // if remote is unicast
            if(t0 == -1) {
                movieName = new String(Arrays.copyOfRange(inPacket.getData(), 0, inPacket.getLength()),StandardCharsets.UTF_8); t0 = System.nanoTime(); continue;
            } else if(inPacket.getLength() == 1) { break; }

            p = outSocket.decrypt(new DatagramPacket(inPacket.getData(), inPacket.getLength(), parseSocketAddress(SafeDatagramSocket.DEFAULT_ADDRESS)));
            if(p == null) { continue; }
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(p, outSocketAddress);
            }
            count += 1; afs += inPacket.getLength();
            System.out.println("*");
        }
        outSocket.printBoxConfigStatus(movieName, count, afs, (double)(System.nanoTime()-t0)/1000000000);
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
