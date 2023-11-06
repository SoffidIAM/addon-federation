package com.soffid.iam.addons.federation.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.ssl.SeyconKeyStore;
import com.soffid.iam.utils.Security;
import com.soffid.test.AbstractHibernateTest;

import es.caib.seycon.ng.ServiceLocator;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class WSFedTest extends AbstractHibernateTest{
	private FederationService svc;

	@Override
	protected void setUp() throws Exception {
		try {
			TestServiceLocator.instance();
			super.setUp();
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public void testFed () throws Throwable
	{
		Security.nestedLogin("master", "anonymuos", Security.ALL_PERMISSIONS);
		try {
			svc = (FederationService) context.getBean(FederationService.SERVICE_NAME);
			EntityGroup eg = createEntityGrou();
			FederationMember idp = createIdp(eg);
			FederationMember sp = createSp(eg);
			final HashMap<String, Object> m = new HashMap<>();
			m.put("firstName", "Gabriel");
			m.put("lastName", "Buades");
			svc.generateWsFedLoginResponse(sp.getPublicId(), idp.getPublicId(), "testUser", 
					m);
		} catch (Throwable t)
		{
			t.printStackTrace();
			throw t;
		} finally {
			Security.nestedLogoff();
		}
	}
	
	private EntityGroup createEntityGrou() throws InternalErrorException {
		EntityGroup egm = new EntityGroup();
		egm.setName("Test");
		return svc.create(egm);
	}

	protected FederationMember createIdp(EntityGroup eg) throws Exception {
		FederationMember idp = new FederationMember();
		idp.setPublicId("idp");
		idp.setClasse("I");
		idp.setEntityGroup(eg);
		idp.setIdpType(IdentityProviderType.SOFFID);
		idp.setHostName("localhost");
		idp.setStandardPort("433");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance ("RSA", "BC"); //$NON-NLS-1$ //$NON-NLS-2$
        SecureRandom random = new SecureRandom ();

        keyGen.initialize (2048,random);
        
        // Generar clave raiz
        KeyPair pair = keyGen.generateKeyPair ();
        X509Name name = new X509Name("CN=localhost,OU=SAML-IDP,O=Soffid"); //$NON-NLS-1$ //$NON-NLS-2$
        X509V3CertificateGenerator generator = getX509Generator(name);
        generator.setSubjectDN(name);
        generator.setPublicKey(pair.getPublic());
        X509Certificate cert = generator.generate(pair.getPrivate(), "BC"); //$NON-NLS-1$
        
		JcaMiscPEMGenerator gen = new JcaMiscPEMGenerator(pair);
        StringWriter w = new StringWriter();
        PemWriter pemWriter = new PemWriter(w);

        pemWriter.writeObject(gen);
        pemWriter.close();

        idp.setPrivateKey(w.getBuffer().toString());

        
        w = new StringWriter();
        pemWriter = new PemWriter(w);
        pemWriter.writeObject(new JcaMiscPEMGenerator(cert) );
        pemWriter.close();
        idp.setCertificateChain(w.getBuffer().toString());
        idp.setMetadades(extractConfigFile("/idp-metadata.xml", idp));

        return svc.create(idp);
	}
	
	protected FederationMember createSp(EntityGroup eg) throws Exception {
		FederationMember sp = new FederationMember();
		sp.setPublicId("sp");
		sp.setClasse("S");
		sp.setEntityGroup(eg);
		sp.setServiceProviderType(ServiceProviderType.WS_FEDERATION);
		sp.setHostName("localhost");
		sp.setStandardPort("433");
		sp.setOpenidUrl(Arrays.asList("https://serviceprovider.test.lab/"));
        return svc.create(sp);
	}

	private X509V3CertificateGenerator getX509Generator(X509Name name) {
        
        long now = System.currentTimeMillis() - 1000 * 60 * 10; // 10 minutos
        long l = now + 1000L * 60L * 60L * 24L * 365L * 5L; // 5 años 
        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        generator.setIssuerDN(name);
        generator.setNotAfter(new Date (l));
        generator.setNotBefore(new Date(now));
        generator.setSerialNumber(BigInteger.valueOf(now));
        generator.setSignatureAlgorithm("sha1WithRSAEncryption"); //$NON-NLS-1$
        return generator;
    }
    

    public String extractConfigFile (String resourceName, FederationMember fm) throws FileNotFoundException, IOException, InternalErrorException {
        String certChain = fm.getCertificateChain();
        String publicCertX509 = null;
		PEMParser pemParser = new PEMParser(new StringReader(certChain));
		JcaX509CertificateConverter converter2 = new JcaX509CertificateConverter().setProvider( "BC" );
		do {
			Object object = pemParser.readObject();
			if (object == null) break;
			if (object instanceof X509CertificateHolder)
			{
				try
				{
					X509Certificate cert = converter2.getCertificate((X509CertificateHolder) object); 
					publicCertX509 = Base64.encodeBytes(cert.getEncoded());
		        } catch (CertificateEncodingException e) {
		            Logger log = LoggerFactory.getLogger(getClass ());
		            log.warn("Error decoding certificate for public id "+fm.getPublicId()); //$NON-NLS-1$
		        } catch (CertificateException e) {
		            Logger log = LoggerFactory.getLogger(getClass ());
		            log.warn("Error decoding certificate for public id "+fm.getPublicId()); //$NON-NLS-1$
				}
		        break;
			}
		} while (true);


        InputStream in = WSFedTest.class.getResourceAsStream(resourceName);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        
        HashMap<String, String> subst = new HashMap<String, String>(1);
        String hostname = fm.getHostName();
        
        String kerberosDomain = fm.getKerberosDomain();
        
        subst.put("${kerberosDomain}", kerberosDomain); //$NON-NLS-1$
        subst.put("${hostName}", hostname); //$NON-NLS-1$
        subst.put("${protocol}", "https"); //$NON-NLS-1$
        subst.put("${sslport}", fm.getClientCertificatePort()); //$NON-NLS-1$
        subst.put("${port}", fm.getStandardPort()); //$NON-NLS-1$
        subst.put("${conf}", "."); //$NON-NLS-1$
        subst.put("${logDir}", "."); //$NON-NLS-1$
        subst.put("${keyPassword}", "***"); //$NON-NLS-1$
        subst.put("${privateKey}", ""); //$NON-NLS-1$
        subst.put("${publicCert}", ""); //$NON-NLS-1$
        subst.put("${publicCertX509}", publicCertX509); //$NON-NLS-1$
        subst.put("${publicId}", fm.getPublicId()); //$NON-NLS-1$
        subst.put("${organization}", fm.getOrganization()); //$NON-NLS-1$
        subst.put("${contact}", fm.getContact()); //$NON-NLS-1$
        
        subst.put("${server}", ""); //$NON-NLS-1$ //$NON-NLS-2$

        new ReplaceFilter(subst).process(in, out);
        
        in.close();
        out.close();
        return out.toString(StandardCharsets.UTF_8.name());
    }

}

