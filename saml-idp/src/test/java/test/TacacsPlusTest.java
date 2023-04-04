package test;

import java.io.IOException;
import java.util.concurrent.TimeoutException;

import com.soffid.iad.addons.federation.idp.tacacs.TacacsClient;

public class TacacsPlusTest {
	private void test1 () throws IOException, TimeoutException {
		String host = "localhost";
		String key = "key";
		
		TacacsClient.main(new String[] {host, key});
	}
	
	public static void main (String args[]) throws IOException, TimeoutException {
		new TacacsPlusTest().test1();
	}
}
