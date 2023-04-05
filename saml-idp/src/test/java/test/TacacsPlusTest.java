package test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeoutException;

import com.soffid.iad.addons.federation.idp.tacacs.AcctReply;
import com.soffid.iad.addons.federation.idp.tacacs.Argument;
import com.soffid.iad.addons.federation.idp.tacacs.AuthenReply;
import com.soffid.iad.addons.federation.idp.tacacs.SessionClient;
import com.soffid.iad.addons.federation.idp.tacacs.TAC_PLUS;
import com.soffid.iad.addons.federation.idp.tacacs.TAC_PLUS.AUTHEN.SVC;
import com.soffid.iad.addons.federation.idp.tacacs.TacacsClient;

public class TacacsPlusTest {
	String host = "localhost";
	String key = "key";
	private void test1 () throws IOException, TimeoutException {
		TacacsClient.main(new String[] {host, key});
	}
	
	private void test2 () throws IOException, TimeoutException {
		TacacsClient tc = new TacacsClient(host, key);
		SessionClient s = tc.newSession(SVC.LOGIN, host, "soffid.bubu.lab", (byte) 15);
		AuthenReply r = s.authenticate_PAP("admin", "changeit");
		System.out.println(r);
	}

	
	private void test3 () throws IOException, TimeoutException, NoSuchAlgorithmException {
		TacacsClient tc = new TacacsClient(host, key);
		SessionClient s = tc.newSession(SVC.LOGIN, host, "soffid.bubu.lab", (byte) 0);
		AuthenReply r = s.authenticate_CHAP("admin", "Geheim03..");
		System.out.println(r);
	}

	private void test4 () throws IOException, TimeoutException, NoSuchAlgorithmException {		
		TacacsClient tc = new TacacsClient(host, key, 5000, true);
		SessionClient s = tc.newSession(SVC.LOGIN, host, "soffid.bubu.lab", (byte) 0);
		
		AcctReply r = s.account(TAC_PLUS.ACCT.FLAG.START.code(), "admin", TAC_PLUS.AUTHEN.METH.LOCAL,
				TAC_PLUS.AUTHEN.TYPE.PAP,
				TAC_PLUS.AUTHEN.SVC.LOGIN, new Argument[0]);
		
		System.out.println(r);

		r = s.account(TAC_PLUS.ACCT.FLAG.STOP.code(), "admin", TAC_PLUS.AUTHEN.METH.LOCAL,
				TAC_PLUS.AUTHEN.TYPE.PAP,
				TAC_PLUS.AUTHEN.SVC.LOGIN, new Argument[0]);

		System.out.println(r);
	}

	public static void main (String args[]) throws IOException, TimeoutException, NoSuchAlgorithmException {
		new TacacsPlusTest().test4();
	}
}
