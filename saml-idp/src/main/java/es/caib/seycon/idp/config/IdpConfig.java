package es.caib.seycon.idp.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.axis.utils.ByteArrayOutputStream;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import es.caib.seycon.idp.client.ServerLocator;
import es.caib.seycon.ng.exception.InternalErrorException;

import com.soffid.iam.addons.federation.common.*;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.api.Password;
import com.soffid.iam.config.Config;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.ssl.SeyconKeyStore;

import es.caib.seycon.util.Base64;


public class IdpConfig {
    String publicId = null;
    com.soffid.iam.api.System system;
    
    public String getFacebookKey ()
    {
    	return getSystem().getParam1();
    }
    
    public String getFacebookSecret ()
    {
    	return getSystem().getParam2();
    }

    public com.soffid.iam.api.System getSystem() {
		return system;
	}

	public void setDispatcher(com.soffid.iam.api.System dispatcher) {
		this.system = dispatcher;
	}

	public String getPublicId() {
        return publicId;
    }
    
    public void setPublicId(String publicId)  {
        this.publicId = publicId;
    }
    
    public void addField (String shortName, String name, String oid) throws InternalErrorException
    {
    	federationService.findAtributs(shortName, "%",	"%"); //$NON-NLS-1$ //$NON-NLS-2$
    }
    public void addFields () 
    {
    	// federationService
    	
    }
    
    
    public void configure () throws FileNotFoundException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, es.caib.seycon.ng.exception.InternalErrorException {
        seyconConfig = Config.getConfig();
        
        RemoteServiceLocator rsl = new RemoteServiceLocator();
        ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
        
        try {
        	federationService = (FederacioService) rsl.getRemoteService(FederacioService.REMOTE_PATH);
        } finally {
        	Thread.currentThread().setContextClassLoader(oldClassLoader);
        }
        
        federationMember = null;
        
        Collection<EntityGroupMember> entityGroups = federationService.findEntityGroupByNom("%"); //$NON-NLS-1$
        for (java.util.Iterator it = entityGroups.iterator(); 
                federationMember == null && it.hasNext(); )
        {
            EntityGroupMember eg = (EntityGroupMember) it.next();
            federationMember = findFederationMember(eg);
        }
        
        if (federationMember == null)
            throw new InternalErrorException("Identity provider "+seyconConfig.getHostName()+" not configured"); //$NON-NLS-1$ //$NON-NLS-2$
        

        extractKeyFile();
    }

    String privateKey;
    public String getPrivateKey() {
        return privateKey;
    }
    public String getPublicCert() {
        return publicCert;
    }
    public FederacioService getFederationService() {
        return federationService;
    }
    public FederationMember getFederationMember() {
        return federationMember;
    }

    String publicCert;
    Config seyconConfig;
    
    private FederacioService federationService;
    private FederationMember federationMember;
    private EntityGroupMember entityGroupMember;
    
    
    public FederationMember findIdentityProviderForRelyingParty (String relyingPartyId) throws InternalErrorException {
    	FederationMember ip = findIdentityProviderForyRelyingParty(entityGroupMember, relyingPartyId);
    	if (ip == null)
    		ip = federationMember;
    	return ip;
    }

    private FederationMember findIdentityProviderForyRelyingParty (EntityGroupMember entityGroupMember, String relyingPartyId) throws InternalErrorException {
    	
        Collection<EntityGroupMember> entities = federationService.findChildren(entityGroupMember);
        for (Iterator<EntityGroupMember> it2 = entities.iterator(); it2.hasNext(); ) {
            EntityGroupMember egm = it2.next();
            FederationMember fm = egm.getFederationMember();
            if (fm != null && fm.getClasse().equals("V")) {
            	for ( FederationMember serviceProvider: fm.getServiceProvider())
            	{
            		if (serviceProvider.getClasse().equals("S") &&
            				relyingPartyId.equals(serviceProvider.getPublicId()))
            			return fm;
            	}
            }
            fm = findIdentityProviderForyRelyingParty(egm, relyingPartyId);
            if (fm != null)
                return fm;
        }
        return null;
    }
    
    
    public FederationMember findIdentityProvider (String id) throws InternalErrorException {
    	if (federationMember.getPublicId().equals(id))
    		return federationMember;
    	else
    		return findIdentityProvider(entityGroupMember, id);
    }

    private FederationMember findIdentityProvider (EntityGroupMember entityGroupMember, String id) throws InternalErrorException {
    	
        Collection<EntityGroupMember> entities = federationService.findChildren(entityGroupMember);
        for (Iterator<EntityGroupMember> it2 = entities.iterator(); it2.hasNext(); ) {
            EntityGroupMember egm = it2.next();
            FederationMember fm = egm.getFederationMember();
            if (fm != null && fm.getClasse().equals("V") && //$NON-NLS-1$
                    id.equals(fm.getPublicId())) {
                return fm;
            }
            fm = findIdentityProvider(egm, id);
            if (fm != null)
                return fm;
        }
        return null;
    }
    
    private FederationMember findFederationMember (EntityGroupMember eg) throws InternalErrorException {
        Collection<EntityGroupMember> entities = federationService.findChildren(eg);
        for (Iterator<EntityGroupMember> it2 = entities.iterator(); it2.hasNext(); ) {
            EntityGroupMember egm = it2.next();
            FederationMember fm = egm.getFederationMember();
            if (fm != null && fm.getClasse().equals("I") && fm.getInternal() &&  //$NON-NLS-1$
                    getPublicId().equals(fm.getPublicId())) {
                entityGroupMember = egm;
                federationMember = fm;
                return fm;
            }
            fm = findFederationMember(egm);
            if (fm != null)
                return fm;
        }
        return null;
    }
    
    static IdpConfig theConfig = null;
    
    private IdpConfig() throws FileNotFoundException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InternalErrorException, InvalidKeyException, IllegalStateException, NoSuchProviderException, SignatureException {
    }

    public static IdpConfig getConfig() throws FileNotFoundException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InternalErrorException, InvalidKeyException, IllegalStateException, NoSuchProviderException, SignatureException {
        if (theConfig == null)
        {
            theConfig = new IdpConfig();
        }
        return theConfig;
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
    


    public void extractKeyFile () throws FileNotFoundException, IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
        Password p = SeyconKeyStore.getKeyStorePassword();
        
        
        if (federationMember.getPrivateKey() == null) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance ("RSA", "BC"); //$NON-NLS-1$ //$NON-NLS-2$
            SecureRandom random = new SecureRandom ();

            keyGen.initialize (1024,random);
            
            // Generar clave raiz
            KeyPair pair = keyGen.generateKeyPair ();
            X509Name name = new X509Name("CN="+federationMember.getHostName()+",OU=SAML-IDP,O=Soffid"); //$NON-NLS-1$ //$NON-NLS-2$
            X509V3CertificateGenerator generator = getX509Generator(name);
            generator.setSubjectDN(name);
            generator.setPublicKey(pair.getPublic());
            X509Certificate cert = generator.generate(pair.getPrivate(), "BC"); //$NON-NLS-1$
            
            StringWriter w = new StringWriter();
            PEMWriter pw = new PEMWriter(w);
            pw.writeObject(pair);
            pw.close ();
            federationMember.setPrivateKey(w.getBuffer().toString());

            w = new StringWriter();
            pw = new PEMWriter(w);
            pw.writeObject(cert);
            pw.close ();
            federationMember.setCertificateChain(w.getBuffer().toString());
            

            federationService.update(federationMember);
        }
        
        // Now read the private and public key
        PEMReader pm = new PEMReader( new StringReader(federationMember.getPrivateKey()));
        KeyPair kp = (KeyPair) pm.readObject();
        Key k = kp.getPrivate();
        if (federationMember.getCertificateChain() == null) 
        {
            throw new IOException ("Missing certificate chain"); //$NON-NLS-1$
        }
        pm = new PEMReader( new StringReader(federationMember.getCertificateChain()));
        List<Certificate> certs = new LinkedList<Certificate>();
        do
        {
        	Certificate cert = (Certificate) pm.readObject();
        	if (cert == null)
        		break;
        	certs.add(cert);
        } while (true);

        if (federationMember.getPublicKey() == null) {
            StringWriter w = new StringWriter();
            PEMWriter pw = new PEMWriter(w);
            pw.writeObject(kp.getPublic());
            pw.close ();
            federationMember.setPublicKey(w.getBuffer().toString());

            federationService.update(federationMember);
        }
        
		JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder("AES-128-CBC");
		builder.setProvider(BouncyCastleProvider.PROVIDER_NAME);
		builder.setSecureRandom(new SecureRandom());
		PEMEncryptor encryptor = builder.build(p.getPassword().toCharArray());
		
		JcaMiscPEMGenerator gen = new JcaMiscPEMGenerator(k, encryptor);

        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);

        pemWriter.writeObject(gen);
        pemWriter.close();

        privateKey = writer.getBuffer().toString();
        
        writer = new StringWriter();
        pemWriter = new PemWriter(writer);
        pemWriter.writeObject(new JcaMiscPEMGenerator(certs.get(0)) );
        pemWriter.close();
        publicCert = writer.toString();
        
        
        String keystorePath = SeyconKeyStore.getKeyStoreFile().getPath();
        KeyStore ks = KeyStore.getInstance(SeyconKeyStore.getKeyStoreType());
        ks.load(new FileInputStream(keystorePath), p.getPassword().toCharArray());
        ks.setKeyEntry("idp",k, p.getPassword().toCharArray(), certs.toArray(new Certificate[certs.size()])); //$NON-NLS-1$
        ks.store(new FileOutputStream(keystorePath), p.getPassword().toCharArray());
        
    }
    
    public File getConfDir () throws FileNotFoundException, IOException {
        File homeDir = Config.getConfig().getHomeDir();
        File confDir = new File (homeDir, "conf"); //$NON-NLS-1$
        return confDir;
    }
    
    public File getLogDir () throws FileNotFoundException, IOException {
        File homeDir = Config.getConfig().getHomeDir();
        File confDir = new File (homeDir, "log"); //$NON-NLS-1$
        return confDir;
    }
    
    public File extractConfigFile (String name) throws FileNotFoundException, IOException, InternalErrorException {
        return extractConfigFile (name, name, federationMember);
    }
    
    public File extractConfigFile (String resourceName, String fileName, FederationMember fm) throws FileNotFoundException, IOException, InternalErrorException {
        File logDir = getLogDir();
        File confDir = getConfDir();

        String certChain = null;
        if (fm != null)
            certChain = fm.getCertificateChain();
        if (federationMember != null && (certChain == null || certChain.length() == 0))
            certChain = federationMember.getCertificateChain();
        
        PEMReader pm = new PEMReader( new StringReader(certChain));
        Certificate cert = (Certificate) pm.readObject();
        String publicCertX509 = null;
        try {
            if (cert != null)
                publicCertX509 = Base64.encodeBytes(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            Logger log = LoggerFactory.getLogger(getClass ());
            log.warn("Error decoding certificate for public id "+fm.getPublicId()); //$NON-NLS-1$
        }

        File f = new File (confDir, fileName);
        
        logDir.mkdirs();
        
        InputStream in = IdpConfig.class.getResourceAsStream(resourceName);
        OutputStream out = new FileOutputStream(f);
        
        HashMap<String, String> subst = new HashMap<String, String>(1);
        String hostname = getHostName();
        
        String kerberosDomain = fm.getKerberosDomain();
        
        subst.put("${kerberosDomain}", kerberosDomain); //$NON-NLS-1$
        subst.put("${hostName}", hostname); //$NON-NLS-1$
        if (getFederationMember().getDisableSSL() == null ||
        		! getFederationMember().getDisableSSL().booleanValue())
            subst.put("${protocol}", "https"); //$NON-NLS-1$
        else
            subst.put("${protocol}", "http"); //$NON-NLS-1$
        subst.put("${sslport}", Integer.toString(getClientCertPort())); //$NON-NLS-1$
        subst.put("${port}", Integer.toString(getStandardPort())); //$NON-NLS-1$
        subst.put("${conf}", confDir.getAbsolutePath()); //$NON-NLS-1$
        subst.put("${logDir}", logDir.getAbsolutePath()); //$NON-NLS-1$
        String p = SeyconKeyStore.getKeyStorePassword().getPassword()
                .replace("&", "&amp;") //$NON-NLS-1$ //$NON-NLS-2$
                .replace("'", "&apos;") //$NON-NLS-1$ //$NON-NLS-2$
                .replace("\"", "&quot;") //$NON-NLS-1$ //$NON-NLS-2$
                .replace("<", "&lt;") //$NON-NLS-1$ //$NON-NLS-2$
                .replace(">", "&gt;"); //$NON-NLS-1$ //$NON-NLS-2$
                
        subst.put("${keyPassword}", p); //$NON-NLS-1$
        subst.put("${privateKey}", privateKey); //$NON-NLS-1$
        subst.put("${publicCert}", publicCert); //$NON-NLS-1$
        subst.put("${publicCertX509}", publicCertX509); //$NON-NLS-1$
        subst.put("${publicId}", fm.getPublicId()); //$NON-NLS-1$
        subst.put("${organization}", fm.getOrganization()); //$NON-NLS-1$
        subst.put("${contact}", fm.getContact()); //$NON-NLS-1$
        
        subst.put("${server}", ServerLocator.getInstance().getServerUrl("").toString()); //$NON-NLS-1$ //$NON-NLS-2$

        new ReplaceFilter(subst).process(in, out);
        
        in.close();
        out.close();
        return f;
    }
    
    public int getClientCertPort() {
        if (federationMember.getStandardPort()  == null)
            return 1443;
        else
            return Integer.decode(federationMember.getClientCertificatePort());
    }
    
    public int getStandardPort() {
        if (federationMember.getStandardPort()  == null)
            return 443;
        else
            return Integer.decode(federationMember.getStandardPort());
    }
    
    public String getHostName() {
        return federationMember.getHostName();
    }
    
    @SuppressWarnings("rawtypes")
    private FederationMember updateMetadata (EntityGroupMember eg) throws FileNotFoundException, IOException, InternalErrorException {
        Collection entities = federationService.findChildren(eg);
        for (java.util.Iterator it2 = entities.iterator(); it2.hasNext(); ) {
            EntityGroupMember egm = (EntityGroupMember) it2.next();
            FederationMember fm = egm.getFederationMember();
            if (fm != null && fm.getClasse().equals("V")) { //$NON-NLS-1$
                
                // Generakte keys
                if (fm.getPrivateKey() == null) 
                {
                    fm.setPrivateKey(federationMember.getPrivateKey());
                    fm.setPublicKey(federationMember.getPublicKey());
                    fm.setCertificateChain(federationMember.getCertificateChain());
                    federationService.update(fm);
                }
                // Generate metadata file
                String fileName = "metadata-"+fm.getId()+".xml"; //$NON-NLS-1$ //$NON-NLS-2$
                
                extractConfigFile("idp-metadata.xml", fileName, fm); //$NON-NLS-1$
                updateMetadata(fm, fileName);
            }
            fm = findFederationMember(egm);
            if (fm != null)
                return fm;
        }
        return null;
    }
    

    public void updateMetadata () throws IOException, InternalErrorException { 
        extractConfigFile("idp-metadata.xml", "idp-metadata.xml", federationMember); //$NON-NLS-1$ //$NON-NLS-2$
        extractConfigFile("spnego.properties", "spnego.properties", federationMember); //$NON-NLS-1$ //$NON-NLS-2$
        extractConfigFile("spnego.conf", "spnego.conf", federationMember); //$NON-NLS-1$ //$NON-NLS-2$
        updateMetadata(federationMember, "idp-metadata.xml"); //$NON-NLS-1$
        updateMetadata (entityGroupMember);
    }
    
    
    public void updateMetadata (FederationMember fm, String fileName) throws IOException, InternalErrorException {
        File confDir = getConfDir();

        File f = new File (confDir, fileName);

        InputStream in = new FileInputStream (f);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte b[] = new byte[4096];
        do {
            int read = in.read(b);
            if (read <= 0) break;
            out.write(b, 0, read);
        } while (true);
        fm.setMetadades(new String(out.toString("UTF-8"))); //$NON-NLS-1$
        federationService.update(fm);
    }
    
    UpdateConfigurationThread upc = null;
    public void generateFederationConfiguration () throws FileNotFoundException, SAXException, IOException, ParserConfigurationException, TransformerException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {

        updateMetadata();
        if (upc != null) {
            upc.end( );
        }
        upc = new UpdateConfigurationThread(this, entityGroupMember);
        upc.doStart();

    }

}
