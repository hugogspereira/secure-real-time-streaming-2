package socket;

import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;

public class DatagramSocketCreator {

    public static DatagramSocket create(InetSocketAddress addr) throws Exception{
        if(addr.getAddress().isMulticastAddress()){
            MulticastSocket inSocketTemp = new MulticastSocket(addr.getPort());
            inSocketTemp.joinGroup(addr, null);
            return inSocketTemp;
        }
	    else 
            return new DatagramSocket(addr);
    }
}
