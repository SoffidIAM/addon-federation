package test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeoutException;

import com.soffid.iad.addons.federation.idp.tacacs.AuthenReply;
import com.soffid.iad.addons.federation.idp.tacacs.SessionClient;
import com.soffid.iad.addons.federation.idp.tacacs.TAC_PLUS.AUTHEN.SVC;
import com.soffid.iad.addons.federation.idp.tacacs.TacacsClient;

public class TacacsPlusTest {
	private void test1 () throws IOException, TimeoutException {
		String host = "localhost";
		String key = "key";
		
		TacacsClient.main(new String[] {host, key});
	}
	
	private void test2 () throws IOException, TimeoutException {
		String host = "localhost";
		String key = "key";
		
		TacacsClient tc = new TacacsClient(host, key);
		SessionClient s = tc.newSession(SVC.LOGIN, host, key, (byte) 0);
		AuthenReply r = s.authenticate_PAP("admin", "changeit");
		System.out.println(r);
	}

	
	private void test3 () throws IOException, TimeoutException, NoSuchAlgorithmException {
		String host = "localhost";
		String key = "key";
		
		TacacsClient tc = new TacacsClient(host, key);
		SessionClient s = tc.newSession(SVC.LOGIN, host, key, (byte) 0);
		AuthenReply r = s.authenticate_CHAP("admin", "Geheim03..");
		System.out.println(r);
	}

	public static void main (String args[]) throws IOException, TimeoutException, NoSuchAlgorithmException {
		new TacacsPlusTest().test3();
	}
}
