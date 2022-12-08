package util;

public class PrintStats {

	public static void toPrintServerConfigStats(String movie, String csuite, String ks, int ksize, String hic) {
		System.out.println("---------------------------------------------");
		System.out.println("Streaming Server observed Indicators and Statistics");
		System.out.println("---------------------------------------------");
		System.out.println("Streamed Movie and used Cryptographic Configs");
		System.out.println("---------------------------------------------");
		System.out.println("Movie (streamed):" +movie );
		System.out.println("Used ciphersuite ALG/MODE/PADDING: " +csuite);
		System.out.println("Used Key (hexadecimal rep.): "+ks);
		System.out.println("Used Keysize: " +ksize);
		System.out.println("Used integrity config: " +hic);
		System.out.println();
	}

	public static void toPrintServerStats(int nf, double afs, long ms, double etm, double fps, double tput) {
		System.out.println("---------------------------------------------");
		System.out.println("Performance indicators of streaming" );
		System.out.println("delivered to receiver Box(es)");
		System.out.println("---------------------------------------------");
		System.out.println("Nr of sent frames: " + nf);
		System.out.println("Average frame size: " + afs);
		System.out.println("Movie size sent (all frames): " + ms);
		System.out.println("Total elapsed time of streamed movie: " + etm);
		System.out.println("Average sent frame rate (frames/sec): " +fps);
		System.out.println("Observed throughput (KBytes/sec): " + tput);
	}

	public static void toPrintBoxConfigStats(String movie, String csuite, String ks, int ksize, String hic) {
		System.out.println("---------------------------------------------");
		System.out.println("Box observed Indicators and Statistics on received stream");
		System.out.println("---------------------------------------------");
		System.out.println("Received Movie and used Cryptographic Configs");
		System.out.println("---------------------------------------------");
		System.out.println("Movie (streamed):" +movie );
		System.out.println("Used ciphersuite ALG/MODE/PADDING: " +csuite);
		System.out.println("Used Key (hexadecimal rep.): "+ks);
		System.out.println("Used Keysize: " +ksize);
		System.out.println("Used integrity config: " +hic);
		System.out.println();
	}

	public static void toPrintBoxStats(int nf, double afs, long ms, double etm, double fps, double tput) {
		System.out.println("---------------------------------------------");
		System.out.println("Performance indicators of received and processed stream" );
		System.out.println("delivered by the Streaming Server)");
		System.out.println("---------------------------------------------");
		System.out.println("Nr of received frames: " + nf);
		System.out.println("Observed average frame size: " + afs);
		System.out.println("Movie size received (all frames): " + ms);
		System.out.println("Total elapsed time of received movie: " + etm);
		System.out.println("Average sent frame rate (frames/sec): " +fps);
		System.out.println("Observed throughput (KBytes/sec): " + tput);
	}

}
