package com.soffid.iam.addons.federation.test;

import java.io.IOException;
import java.io.InputStream;

import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.test.AbstractHibernateTest;

import es.caib.seycon.ng.exception.InternalErrorException;

public class RSATest extends AbstractHibernateTest {
	@Override
	protected void setUp() throws Exception {
		try {
			super.setUp();
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public void testRsa () throws Throwable
	{
		try {
			FederacioService fed = (FederacioService) context.getBean(FederacioService.SERVICE_NAME);
			InputStream in = getClass().getClassLoader().getResourceAsStream("rsa/pkcs12-test.p12");
			byte b[] = new byte [99999];
			int length = in.read(b);
			String result [] = fed.parsePkcs12(b, "abc123");
			System.out.println ("KEY");
			System.out.println (result[0]);
			System.out.println ("PUBLIC KEY");
			System.out.println (result[1]);
			System.out.println ("CERT CHAIN");
			System.out.println (result[2]);
		} catch (Throwable t)
		{
			t.printStackTrace();
			throw t;
		}
	}

}
