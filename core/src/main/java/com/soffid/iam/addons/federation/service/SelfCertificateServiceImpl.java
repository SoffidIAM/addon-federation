package com.soffid.iam.addons.federation.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECPublicKeySpec;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.mozilla.SignedPublicKeyAndChallenge;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import com.soffid.iam.addons.federation.api.UserCredential;
import com.soffid.iam.addons.federation.common.RootCertificate;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.RootCertificateEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.model.UserEntity;
import com.soffid.iam.ssl.SeyconKeyStore;
import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class SelfCertificateServiceImpl extends SelfCertificateServiceBase {
    private static final String ENCRYPTION_METHOD = "sha256WithRSAEncryption";
	SecureRandom random = new SecureRandom();

	
	private RootCertificateEntity getCurrentRoot ()
	{
		Date lastDate = null;
		RootCertificateEntity last = null;
		for (RootCertificateEntity root: getRootCertificateEntityDao().loadAll())
		{
			if (! root.isObsolete() && !root.isExternal())
			{
				if (lastDate == null || lastDate.before(root.getCreationDate()))
				{
					last = root;
					lastDate = root.getCreationDate();
				}
			}
		}
		return last;
	}
	
	private PrivateKey getPrivateKey () throws IOException, PKCSException, OperatorCreationException
	{
		RootCertificateEntity root = getCurrentRoot ();
		if (root != null)
		{
			byte[] material = root.getPrivateKey();
			final char[] password = getKeyPassword(root);
			
			// Now read the private and public key
			PEMParser pemParser = new PEMParser( new StringReader( new String(material) ));
			Object object = pemParser.readObject();
		    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		    KeyPair kp;
		    PrivateKey pk;
		    if (object instanceof PEMEncryptedKeyPair)
		    {
		        // Encrypted key - we will use provided password
		        PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
		        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password);
		        kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
		        pk = kp.getPrivate();
		    }
		    else if (object instanceof PKCS8EncryptedPrivateKeyInfo )
		    {
		        // Encrypted key - we will use provided password
		    	PKCS8EncryptedPrivateKeyInfo ckp = (PKCS8EncryptedPrivateKeyInfo) object;

				JceOpenSSLPKCS8DecryptorProviderBuilder decryptorBuilder = new JceOpenSSLPKCS8DecryptorProviderBuilder();
				InputDecryptorProvider decryptor = decryptorBuilder.build(password);
				
		        PrivateKeyInfo kpinfo = ckp.decryptPrivateKeyInfo(decryptor);
		        pk = new JcaPEMKeyConverter().getPrivateKey(kpinfo);
		    }
		    else
		    {
		    	kp = converter.getKeyPair((PEMKeyPair) object);
		        pk = kp.getPrivate();
		    }
	    	pemParser.close();
	    	return pk;
		}
		return null;
	}

	private char[] getKeyPassword(RootCertificateEntity root) {
		String key = "Soffid" + root.getId() +"key";
		final char[] password =  key.toCharArray();
		return password;
	}
	
	public SelfCertificateServiceImpl() {
        java.security.Security.addProvider(new BouncyCastleProvider());
	}

    private X509V3CertificateGenerator getX509Generator() throws InternalErrorException {

        long now = System.currentTimeMillis() - 1000 * 60 * 10; // 10 minutos
        long l = now + 1000L * 60L * 60L * 24L * 365L * 5L; // 5 años
        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        X509Certificate rootCert = getRootCertificate();
        
        generator.setIssuerDN(rootCert.getSubjectX500Principal());
        generator.setNotAfter(new Date(l));
        generator.setNotBefore(new Date(now));
        generator.setSerialNumber(BigInteger.valueOf(now));
        generator.setSignatureAlgorithm(ENCRYPTION_METHOD);
        return generator;
    }

	@Override
	protected X509Certificate handleCreate(String description, String pkcs10) throws Exception {
		Base64Encoder b64 = new Base64Encoder();
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		b64.decode(pkcs10, out);
		SignedPublicKeyAndChallenge spk = new SignedPublicKeyAndChallenge(out.toByteArray());
		if (!spk.verify("BC"))
		{
			throw new InternalErrorException ("Certificate request signature verficatin has failed");
		}
		PublicKey pk = spk.getPublicKey("BC");
		X509Certificate cert = generateUserCertificate(Security.getCurrentUser(), pk, description);
        
        return cert;
	}

	private X509Certificate generateUserCertificate(String userName, PublicKey pk, String description)
			throws InternalErrorException, NoSuchProviderException,
			SignatureException, InvalidKeyException, IOException,
			CertificateEncodingException, SecurityException, OperatorCreationException, PKCSException {
		RootCertificateEntity root = getCurrentRoot();
		if (root == null)
			throw new InternalErrorException("There is no valid certificate authority. Please, contact your administrator");

		UserEntity user = getUserEntityDao().findByUserName(userName);
        String name = "CN=" + userName + ",CN=" + description +",O="+root.getOrganizationName();
        
        // Register certificate on data base
        UserCredentialEntity entity = getUserCredentialEntityDao().newUserCredentialEntity();
        entity.setDescription(description);
        Calendar c = Calendar.getInstance();
        c.add(Calendar.MONTH, root.getUserCertificateMonths());
        entity.setExpirationDate(c.getTime());
        entity.setCreated(new Date());
        entity.setUserId(user.getId());
        entity.setRoot(root);
        entity.setType(UserCredentialType.CERT);
        entity.setKey("-");
        entity.setSerialNumber(getUserCredentialService().generateNextSerial());
        getUserCredentialEntityDao().create(entity);

        // Now, generate the certificate
        X509V3CertificateGenerator generator = getX509Generator();
        generator.setSubjectDN(new X509Name(name));
        generator.setPublicKey(pk);
        generator.setNotAfter(entity.getExpirationDate());
        c = Calendar.getInstance();
        c.add(Calendar.MINUTE, -10);
        generator.setNotBefore(c.getTime());
        generator.setSerialNumber(new BigInteger(entity.getSerialNumber()));
        
        X509Certificate cert = generator.generateX509Certificate(getPrivateKey(), "BC");
        
        entity.setKey( Base64.encodeBytes(cert.getPublicKey().getEncoded(), Base64.DONT_BREAK_LINES));
        entity.setCertificate( Base64.encodeBytes(cert.getPublicKey().getEncoded(), Base64.DONT_BREAK_LINES));
        getUserCredentialEntityDao().update(entity);
		return cert;
	}

	@Override
	protected List<UserCredential> handleFindByUser(String userName)
			throws Exception {
		UserEntity user = getUserEntityDao().findByUserName(userName);
		List<UserCredential> certs = new LinkedList<>();
		for (UserCredentialEntity entity: getUserCredentialEntityDao().findByUserId(user.getId())) {
			if (entity.getType() == UserCredentialType.CERT) 
				certs.add(getUserCredentialEntityDao().toUserCredential(entity));
		}
		
		Collections.sort(certs, new Comparator<UserCredential>() {
			public int compare(UserCredential o1, UserCredential o2) {
				if (o1.getCreated().after(o2.getCreated()))
					return -1;
				else if (o2.getCreated().after(o1.getCreated()))
					return +1;
				else
					return 0;
			};
		});
		return certs;
	}

	@Override
	protected UserCredential handleFindByCertificate(
			X509Certificate certificate) throws Exception {
		String pk = Base64.encodeBytes(certificate.getPublicKey().getEncoded(), Base64.DONT_BREAK_LINES);
		String cert = Base64.encodeBytes(certificate.getEncoded(), Base64.DONT_BREAK_LINES);
		for (UserCredentialEntity cred: getUserCredentialEntityDao().findByPublicKey(pk)) {
			if (cert.equals(cred.getCertificate()))
				return getUserCredentialEntityDao().toUserCredential(cred);
		}
		return null;
	}

	@Override
	protected RootCertificate handleCreateRootCertificate(RootCertificate root) throws Exception {
		RootCertificateEntity rootEntity = getRootCertificateEntityDao().newRootCertificateEntity();
		if (root.isExternal()) {
			rootEntity = getRootCertificateEntityDao().rootCertificateToEntity(root);
			rootEntity.setCertificate(root.getCertificate().getEncoded());
		} else {
	        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
	
	        keyGen.initialize(2048, random);
	
	        // Generar clave raiz
	        KeyPair pair = keyGen.generateKeyPair();
	        
	        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
	        String dn = "CN=Soffid Self-certify addon,O="+root.getOrganizationName();
	        generator.setIssuerDN( new X500Principal(dn));
	        generator.setSerialNumber(BigInteger.valueOf(1));
	        generator.setSignatureAlgorithm(ENCRYPTION_METHOD);
	        Calendar c = Calendar.getInstance();
	        c.add(Calendar.MINUTE, -10);
	        generator.setNotBefore(c.getTime());
	        generator.setNotAfter(root.getExpirationDate().getTime());
	        generator.setPublicKey(pair.getPublic());
	        generator.setSubjectDN(new X500Principal(dn));
	        generator.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true) );
	        X509Certificate cert = generator.generateX509Certificate(pair.getPrivate(), "BC");
	
	        rootEntity.setCertificate(cert.getEncoded());
	        rootEntity.setCreationDate(new Date());
	        rootEntity.setExpirationDate(root.getExpirationDate().getTime());
	        rootEntity.setObsolete(false);
	        rootEntity.setOrganizationName(root.getOrganizationName());
	        rootEntity.setUserCertificateMonths(root.getUserCertificateMonths());
	        rootEntity.setPrivateKey(new byte[] {0});
	        getRootCertificateEntityDao().create(rootEntity);
	        
	        StringWriter writer = new StringWriter();
	
	        
			final char[] password = getKeyPassword(rootEntity);
	
			JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
	        encryptorBuilder.setRandom( new SecureRandom());
	        encryptorBuilder.setPasssword(password);
	        OutputEncryptor oe = encryptorBuilder.build();
	        JcaPKCS8Generator gen = new JcaPKCS8Generator( pair.getPrivate(),oe);
	        PemObject obj = gen.generate();
	        
	        PemWriter pemWriter = new PemWriter(writer);
	        pemWriter.writeObject(obj);
	        pemWriter.close();
	        
	        rootEntity.setPrivateKey(writer.getBuffer().toString().getBytes("UTF-8"));
		} 
        getRootCertificateEntityDao().create(rootEntity);
        
        return getRootCertificateEntityDao().toRootCertificate(rootEntity);
	}

	@Override
	protected X509Certificate handleGetRootCertificate() throws Exception {
		RootCertificateEntity root = getCurrentRoot();
		if (root == null)
			return null;
		else
			return getRootCertificateEntityDao().toRootCertificate(root).getCertificate();
	}

	@Override
	protected int handleGetUserCertificateDuration() throws Exception {
		RootCertificateEntity root = getCurrentRoot();
		return root.getUserCertificateMonths();
	}

	@Override
	protected void handleUpdateRootCertificate(RootCertificate root)
			throws Exception {
		RootCertificateEntity rootEntity = getRootCertificateEntityDao().load(root.getId());
		rootEntity.setUserCertificateMonths(root.getUserCertificateMonths());
		rootEntity.setGuessUserScript(root.getGuessUserScript());
		getRootCertificateEntityDao().update(rootEntity);
	}

	@Override
	protected List<RootCertificate> handleGetRootCertificates()
			throws Exception {
		List<RootCertificate> list = new LinkedList<>();
		for (RootCertificateEntity entity: getRootCertificateEntityDao().loadAll()) {
			if (!entity.isObsolete())
				list.add(getRootCertificateEntityDao().toRootCertificate(entity));
		}
		Collections.sort(list, new Comparator<RootCertificate>() {
			public int compare(RootCertificate o1, RootCertificate o2) {
				if (o1.getCreationDate().after(o2.getCreationDate()))
					return -1;
				else if (o2.getCreationDate().after(o1.getCreationDate()))
					return +1;
				else
					return 0;
			};
		});
		return list;
	}

	@Override
	protected byte[] handleCreatePkcs12(String description, String password)
			throws Exception {
		return handleCreatePkcs12(Security.getCurrentUser(), description, password);
	}
	
	@Override
	protected byte[] handleCreatePkcs12(String user, String description, String password)
			throws Exception {
		KeyPair keypair = generateKeyPair ();
		X509Certificate cert = generateUserCertificate(user, keypair.getPublic(), description);
		
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);

        X509Certificate[] chain = new X509Certificate[2];
        // first the client, then the CA certificate
        chain[0] = cert;
        chain[1] = getRootCertificate();
        
        store.setKeyEntry("mykey", keypair.getPrivate(), password.toCharArray(), chain);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        store.store(out, password.toCharArray());
        out.close();
        return out.toByteArray();
	}

	private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
         keyGen.initialize(2048, random);
         KeyPair keypair = keyGen.generateKeyPair();
         return keypair;
    }

	@Override
	protected void handleRevokeRootCertificate(RootCertificate root) throws Exception {
		RootCertificateEntity rootEntity = getRootCertificateEntityDao().load(root.getId());
		rootEntity.setObsolete(true);
		getRootCertificateEntityDao().update(rootEntity);
	}

	
}
