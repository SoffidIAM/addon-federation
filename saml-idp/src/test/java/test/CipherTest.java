package test;

import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocketFactory;

public class CipherTest {
	public static void main (String [] args) throws NoSuchAlgorithmException
	{
		SSLEngine engine = SSLContext.getDefault().createSSLEngine();
		for (String e: engine.getSupportedCipherSuites())
			System.out.println (e);
	}
}
