package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.io.StringReader;
import java.lang.ref.WeakReference;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.locks.Lock;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.opensaml.common.binding.security.IssueInstantRule;
import org.opensaml.common.binding.security.MessageReplayRule;
import org.opensaml.common.binding.security.SAMLProtocolMessageXMLSignatureSecurityPolicyRule;
import org.opensaml.saml2.binding.security.SAML2AuthnRequestsSignedRule;
import org.opensaml.saml2.binding.security.SAML2HTTPPostSimpleSignRule;
import org.opensaml.saml2.binding.security.SAML2HTTPRedirectDeflateSignatureRule;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.ReplayCache;
import org.opensaml.ws.security.provider.MandatoryAuthenticatedMessageRule;
import org.opensaml.ws.security.provider.MandatoryIssuerRule;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoProvider;
import org.opensaml.xml.security.keyinfo.provider.DSAKeyValueProvider;
import org.opensaml.xml.security.keyinfo.provider.InlineX509DataProvider;
import org.opensaml.xml.security.keyinfo.provider.RSAKeyValueProvider;
import org.opensaml.xml.security.trust.ChainingTrustEngine;
import org.opensaml.xml.security.trust.ExplicitKeyTrustEngine;
import org.opensaml.xml.security.trust.TrustEngine;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.PKIXTrustEngine;
import org.opensaml.xml.security.x509.PKIXX509CredentialTrustEngine;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ChainingSignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.signature.impl.PKIXSignatureTrustEngine;
import org.opensaml.xml.util.DatatypeHelper;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.SAMLProfile;
import com.soffid.iam.addons.federation.common.SAMLRequirementEnumeration;
import com.soffid.iam.addons.federation.common.SamlProfileEnumeration;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.utils.Security;

import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML1AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.binding.security.ShibbolethClientCertAuthRule;
import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.AbstractSAMLProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.CryptoOperationRequirementLevel;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.ArtifactResolutionConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml1.AttributeQueryConfiguration;
import edu.internet2.middleware.shibboleth.common.security.MetadataPKIXValidationInformationResolver;
import edu.internet2.middleware.shibboleth.common.security.ShibbolethSecurityPolicy;
import edu.internet2.middleware.shibboleth.common.service.ServiceException;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;

public class RelyingPartyConfigurationManager extends SAMLMDRelyingPartyConfigurationManager {
	HashMap<String,WeakReference<RelyingPartyConfiguration>> configurationCache = new HashMap<>();
	private SoffidMetadataProvider metadataProvider;
	private SAML2AttributeAuthority saml2AttributeAuthority;
	private SAML1AttributeAuthority saml1AttributeAuthority;
	Log log = LogFactory.getLog(getClass());
	private ChainingSignatureTrustEngine signatureTrustEngine;
	private ChainingTrustEngine<X509Credential> credentialTrustEngine;
	
	public RelyingPartyConfigurationManager() {
		metadataProvider = new SoffidMetadataProvider();
	}

	public void onNewContextCreated(ApplicationContext newServiceContext) throws edu.internet2.middleware.shibboleth.common.service.ServiceException {
    	// super.onNewContextCreated(newServiceContext);
		try {
			saml2AttributeAuthority = (SAML2AttributeAuthority) newServiceContext.getBean("shibboleth.SAML2AttributeAuthority");
			saml1AttributeAuthority = (SAML1AttributeAuthority) newServiceContext.getBean("shibboleth.SAML1AttributeAuthority");

			createCredentialTrustEngine();
			createSignatureTrustEngine();
		} catch (Exception e) {
			throw new RuntimeException("Error generating relying-party configuration manager", e);
		}
	}

	private void createCredentialTrustEngine() {
		credentialTrustEngine = new ChainingTrustEngine<X509Credential>();
		List list = credentialTrustEngine.getChain();
		{
	        MetadataCredentialResolver credResolver = new org.opensaml.security.MetadataCredentialResolver(metadataProvider);;
	        final ExplicitKeyTrustEngine engine = new ExplicitKeyTrustEngine(credResolver);
			list.add( engine );
		}
		{
	        MetadataPKIXValidationInformationResolver pviResolver = new MetadataPKIXValidationInformationResolver(
	                metadataProvider);
	        
	        PKIXTrustEngine<X509Credential> engine = new PKIXX509CredentialTrustEngine(pviResolver);
	        TrustEngine<X509Credential> e = (TrustEngine<X509Credential>) engine;
	        list.add( e );
		}
	}

	public void createSignatureTrustEngine() {
		signatureTrustEngine = new org.opensaml.xml.signature.impl.ChainingSignatureTrustEngine();
		List<SignatureTrustEngine> trustEngines = signatureTrustEngine.getChain();
		{
			MetadataCredentialResolver credResolver = new MetadataCredentialResolver(metadataProvider);
		    List<KeyInfoProvider> keyInfoProviders = new ArrayList<KeyInfoProvider>();
		    keyInfoProviders.add(new DSAKeyValueProvider());
		    keyInfoProviders.add(new RSAKeyValueProvider());
		    keyInfoProviders.add(new InlineX509DataProvider());
		    KeyInfoCredentialResolver keyInfoCredResolver = new BasicProviderKeyInfoCredentialResolver(keyInfoProviders);
		    ExplicitKeySignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(credResolver, keyInfoCredResolver);
		    trustEngines.add(engine);
		}
		{
		    MetadataPKIXValidationInformationResolver pviResolver = new MetadataPKIXValidationInformationResolver(metadataProvider);

		    List<KeyInfoProvider> keyInfoProviders = new ArrayList<KeyInfoProvider>();
		    keyInfoProviders.add(new DSAKeyValueProvider());
		    keyInfoProviders.add(new RSAKeyValueProvider());
		    keyInfoProviders.add(new InlineX509DataProvider());
		    KeyInfoCredentialResolver keyInfoCredResolver = new BasicProviderKeyInfoCredentialResolver(keyInfoProviders);

		    PKIXSignatureTrustEngine engine = new PKIXSignatureTrustEngine(pviResolver, keyInfoCredResolver);
		    trustEngines.add(engine);
		}
	}
	
	@Override
	public RelyingPartyConfiguration getAnonymousRelyingConfiguration() {
		try {
			IdpConfig c = IdpConfig.getConfig();
			String publicId = c.getFederationMember().getPublicId();
			return getRelyingPartyConfiguration(c, publicId);
		} catch (Exception e) {
			throw new RuntimeException("Error fetching relying party configuration", e);
		}
	}


	protected RelyingPartyConfiguration getRelyingPartyConfiguration(IdpConfig c, String publicId) throws InternalErrorException, IOException {
		WeakReference<RelyingPartyConfiguration> cached = configurationCache.get(Security.getCurrentTenantName()+"\\"+publicId);
		RelyingPartyConfiguration rp2 = cached == null ? null: cached.get();
		if (rp2 == null) {
			rp2 = new RelyingPartyConfiguration(publicId);
			rp2.setDefaultAuthenticationMethod("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
			rp2.setDefaultSigningCredential(getCredential());
			FederationService svc = (FederationService) new RemoteServiceLocator().getFederacioService();
			FederationMember fm = svc.findFederationMemberByPublicId(publicId);
			if (fm == null)
				throw new InternalErrorException("Unable to find profiles for "+publicId);
			addProfiles(rp2, fm);
			configurationCache.put(Security.getCurrentTenantName()+"\\"+publicId, new WeakReference<RelyingPartyConfiguration>(rp2));
		}
		return rp2;
	}

	private Credential getCredential() throws InternalErrorException {
		try {
			IdpConfig c = IdpConfig.getConfig();
			FederationMember federationMember = c.getFederationMember();
			// Now read the private and public key
			PEMParser pemParser = new PEMParser(new StringReader(federationMember.getPrivateKey()));
			Object object = pemParser.readObject();
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

			KeyPair keyPair = converter.getKeyPair((PEMKeyPair) object);
			pemParser.close();
			
			JcaX509CertificateConverter converter2 = new JcaX509CertificateConverter().setProvider( "BC" );
			if (federationMember.getCertificateChain() == null) 
			{
			    throw new IOException ("Missing certificate chain"); //$NON-NLS-1$
			}
			
			LinkedList<X509Certificate> certs = new LinkedList<X509Certificate>();
			pemParser = new PEMParser(new StringReader(federationMember.getCertificateChain()));
			do {
				object = pemParser.readObject();
				if (object == null) break;
				if (object instanceof X509CertificateHolder)
				{
					certs.add(converter2.getCertificate((X509CertificateHolder) object));
				}
			} while (true);

			BasicX509Credential credential = new BasicX509Credential();
			credential.setPrivateKey(keyPair.getPrivate());
			credential.setEntityCertificateChain(certs);
			credential.setEntityCertificate(certs.get(0));
			return credential;
		} catch (UnrecoverableKeyException | InvalidKeyException | KeyStoreException | NoSuchAlgorithmException
				| CertificateException | IllegalStateException | NoSuchProviderException | SignatureException
				| IOException | InternalErrorException e) {
			throw new InternalErrorException("Error parsing certificate", e);
		}
	}

	ReplayCache replayCache = new org.opensaml.util.storage.ReplayCache(
			new MapBasedStorageService<>(), 1_200_000); // 20 minutes
	private ParserPool parserPool = new BasicParserPool();
	
	private void addProfiles(RelyingPartyConfiguration rp2, FederationMember federationMember) throws IOException, InternalErrorException {
		FederationService federationService = new RemoteServiceLocator().getFederacioService();
		rp2.getProfileConfigurations().clear();
		for (SAMLProfile profile: federationService.findProfilesByFederationMember(federationMember)) {
            if (! profile.getClasse().equals( SamlProfileEnumeration.OPENID) &&
            		! profile.getClasse().equals( SamlProfileEnumeration.WS_FEDERATION)
            		&& Boolean.TRUE.equals(profile.getEnabled()) )
            {
				AbstractSAMLProfileConfiguration pc = null;
	            SamlProfileEnumeration type = profile.getClasse();
	            if (type.equals(SamlProfileEnumeration.SAML1_AQ)) {
	            	pc = createSaml1AttributeQueryProfile(profile);
	            } else if (type.equals(SamlProfileEnumeration.SAML1_AR)) {
	            	pc = createSaml1AttributeResolutionProfile();

	            } else if (type.equals(SamlProfileEnumeration.SAML2_AR)) {
	            	pc = createSaml2AttributeResolutionProfile(profile);

	            } else if (type.equals(SamlProfileEnumeration.SAML2_AQ)) {
	            	pc = createSaml2AttributeQueryProfile(profile);

	            } else if (type.equals(SamlProfileEnumeration.SAML2_SSO)) {
	            	pc = createSaml2SloProfile(federationMember, type, profile);
		            pc.setSignRequests(parseCrypto(profile.getSignRequests(), CryptoOperationRequirementLevel.never));
		            pc.setSignAssertions(parseCrypto(profile.getSignAssertions(), CryptoOperationRequirementLevel.never));
		            pc.setSignResponses(parseCrypto(profile.getSignResponses(), CryptoOperationRequirementLevel.never));
		            pc.setSigningCredential(getCredential());
		            rp2.getProfileConfigurations().put(pc.getProfileId(), pc);
		            pc = createSaml2SsoProfile(federationMember, type, profile);
	            } else if (type.equals(SamlProfileEnumeration.SAML2_ECP)) {
	            	pc = crateSamlECPProfile(federationMember, profile, type);
	            } else {
	            	continue;
	            }
	
	            if (profile.getAssertionLifetime() != null) {
	                long lifetime = SpringConfigurationUtils.parseDurationToMillis("'assertionLifetime' on profile configuration of type " + type + " of " + federationMember,
	                        profile.getAssertionLifetime(), 0);
	                pc.setAssertionLifetime(lifetime);
	            }
	            if (profile.getOutboundArtifactType() != null) {
	                byte[] artifactTypeBytes = DatatypeHelper.intToByteArray(Integer.parseInt(profile.getOutboundArtifactType()));
	                byte[] trimmedArtifactTypeBytes = { artifactTypeBytes[2], artifactTypeBytes[3] };
	                pc.setOutboundArtifactType( trimmedArtifactTypeBytes);
	            } else {
	            	pc.setOutboundArtifactType(null);
	            }
	            pc.setSignRequests(parseCrypto(profile.getSignRequests(), CryptoOperationRequirementLevel.never));
	            pc.setSignAssertions(parseCrypto(profile.getSignAssertions(), CryptoOperationRequirementLevel.never));
	            pc.setSignResponses(parseCrypto(profile.getSignResponses(), CryptoOperationRequirementLevel.never));
	            pc.setSigningCredential(getCredential());
	            rp2.getProfileConfigurations().put(pc.getProfileId(), pc);
            }
		}
	}

	public AbstractSAMLProfileConfiguration crateSamlECPProfile(FederationMember federationMember, SAMLProfile profile,
			SamlProfileEnumeration type) {
		AbstractSAMLProfileConfiguration pc;
		edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.ECPConfiguration ecp = 
				new edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.ECPConfiguration();
		pc = ecp;
		if (profile.getAssertionLifetime() != null) {
		    long lifetime = SpringConfigurationUtils.parseDurationToMillis("'assertionLifetime' on profile configuration of type " + type + " of " + federationMember,
		            profile.getAssertionLifetime(), 0);
		    ecp.setAssertionLifetime(lifetime);
		}
		ecp.setProxyCount(profile.getAssertionProxyCount() == null? 0: profile.getAssertionProxyCount().intValue());
		ecp.setEncryptNameID(parseCrypto(profile.getEncryptNameIds(), CryptoOperationRequirementLevel.never));
		ecp.setEncryptAssertion(parseCrypto(profile.getEncryptAssertions(), CryptoOperationRequirementLevel.never));
		if (profile.getMaximumSPSessionLifetime() != null) {
		    long lifetime = SpringConfigurationUtils.parseDurationToMillis("'maximumSPSessionLifetime' on profile configuration of type " + type + " of " + federationMember,
		            profile.getMaximumSPSessionLifetime(), 300); // 5 minutes
		    ecp.setMaximumSPSessionLifetime(lifetime);
		}
		ecp.setIncludeAttributeStatement(profile.getIncludeAttributeStatement() == null? false: profile.getIncludeAttributeStatement().booleanValue());
		ecp.setAttributeAuthority(saml2AttributeAuthority);
		return pc;
	}

	public AbstractSAMLProfileConfiguration createSaml1AttributeQueryProfile(SAMLProfile profile) {
		AbstractSAMLProfileConfiguration pc;
		AttributeQueryConfiguration aqc = new AttributeQueryConfiguration();
		pc = aqc;
		if (profile.getOutboundArtifactType() != null) {
		    byte[] artifactTypeBytes = DatatypeHelper.intToByteArray(Integer.parseInt(profile.getOutboundArtifactType()));
		    byte[] trimmedArtifactTypeBytes = { artifactTypeBytes[2], artifactTypeBytes[3] };
		    aqc.setOutboundArtifactType( trimmedArtifactTypeBytes);
		} else {
			aqc.setOutboundArtifactType(null);
		}
		aqc.setAttributeAuthority(saml1AttributeAuthority);

		ShibbolethSecurityPolicy sp = new ShibbolethSecurityPolicy("shibboleth.SAML1AttributeQuerySecurityPolicy");
		sp.getPolicyRules().add( new MessageReplayRule(replayCache) );
		sp.getPolicyRules().add( new IssueInstantRule(300, 300));
		sp.getPolicyRules().add( new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(signatureTrustEngine));
		sp.getPolicyRules().add( new ShibbolethClientCertAuthRule(credentialTrustEngine));
		sp.getPolicyRules().add( new MandatoryIssuerRule());
		sp.getPolicyRules().add( new MandatoryAuthenticatedMessageRule());
		aqc.setSecurityPolicy(sp);
		return pc;
	}

	public AbstractSAMLProfileConfiguration createSaml1AttributeResolutionProfile() {
		AbstractSAMLProfileConfiguration pc;
		ArtifactResolutionConfiguration arc = 
				new ArtifactResolutionConfiguration();
		pc = arc;
		arc.setAttributeAuthority(saml1AttributeAuthority);
		
		ShibbolethSecurityPolicy sp = new ShibbolethSecurityPolicy("shibboleth.SAML1ArtifactResolutionSecurityPolicy");
		sp.getPolicyRules().add( new MessageReplayRule(replayCache) );
		sp.getPolicyRules().add( new IssueInstantRule(300, 300));
		sp.getPolicyRules().add( new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(signatureTrustEngine));
		sp.getPolicyRules().add( new ShibbolethClientCertAuthRule(credentialTrustEngine));
		sp.getPolicyRules().add( new MandatoryIssuerRule());
		sp.getPolicyRules().add( new MandatoryAuthenticatedMessageRule());
		arc.setSecurityPolicy(sp);
		return pc;
	}

	public AbstractSAMLProfileConfiguration createSaml2AttributeResolutionProfile(SAMLProfile profile) {
		AbstractSAMLProfileConfiguration pc;
		edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.ArtifactResolutionConfiguration arc = 
				new edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.ArtifactResolutionConfiguration();
		pc = arc;
		arc.setEncryptNameID(parseCrypto(profile.getEncryptNameIds(), CryptoOperationRequirementLevel.never));
		arc.setEncryptAssertion(parseCrypto(profile.getEncryptAssertions(), CryptoOperationRequirementLevel.never));
		arc.setProxyCount(profile.getAssertionProxyCount() == null ? Integer.MAX_VALUE: profile.getAssertionProxyCount().intValue());
		arc.setAttributeAuthority(saml2AttributeAuthority);
		
		ShibbolethSecurityPolicy sp = new ShibbolethSecurityPolicy("shibboleth.SAML2SSOSecurityPolicy");
		sp.getPolicyRules().add( new MessageReplayRule(replayCache) );
		sp.getPolicyRules().add( new IssueInstantRule(300, 300));
		sp.getPolicyRules().add( new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(signatureTrustEngine));

		sp.getPolicyRules().add( new SAML2HTTPRedirectDeflateSignatureRule(signatureTrustEngine));
		{
			List<KeyInfoProvider> keyInfoProviders = new ArrayList<KeyInfoProvider>();
			keyInfoProviders.add(new DSAKeyValueProvider());
			keyInfoProviders.add(new RSAKeyValueProvider());
			keyInfoProviders.add(new InlineX509DataProvider());
			KeyInfoCredentialResolver keyInfoCredResolver = new BasicProviderKeyInfoCredentialResolver(keyInfoProviders);
			sp.getPolicyRules().add( new SAML2HTTPPostSimpleSignRule(signatureTrustEngine, parserPool, keyInfoCredResolver));
		}
		sp.getPolicyRules().add( new ShibbolethClientCertAuthRule(credentialTrustEngine));
		sp.getPolicyRules().add( new MandatoryIssuerRule());
		sp.getPolicyRules().add( new MandatoryAuthenticatedMessageRule());
		arc.setSecurityPolicy(sp);
		return pc;
	}

	public AbstractSAMLProfileConfiguration createSaml2AttributeQueryProfile(SAMLProfile profile) {
		AbstractSAMLProfileConfiguration pc;
		edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AttributeQueryConfiguration aqc = 
				new edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AttributeQueryConfiguration();
		pc = aqc;
		if (profile.getOutboundArtifactType() != null) {
		    byte[] artifactTypeBytes = DatatypeHelper.intToByteArray(Integer.parseInt(profile.getOutboundArtifactType()));
		    byte[] trimmedArtifactTypeBytes = { artifactTypeBytes[2], artifactTypeBytes[3] };
		    aqc.setOutboundArtifactType( trimmedArtifactTypeBytes);
		} else {
			aqc.setOutboundArtifactType(null);
		}
		aqc.setEncryptNameID(parseCrypto(profile.getEncryptNameIds(), CryptoOperationRequirementLevel.never));
		aqc.setEncryptAssertion(parseCrypto(profile.getEncryptAssertions(), CryptoOperationRequirementLevel.never));
		aqc.setProxyCount(profile.getAssertionProxyCount() == null? 0: profile.getAssertionProxyCount().intValue());
		aqc.setAttributeAuthority(saml2AttributeAuthority);
		
		ShibbolethSecurityPolicy sp = new ShibbolethSecurityPolicy("shibboleth.SAML2SSOSecurityPolicy");
		sp.getPolicyRules().add( new MessageReplayRule(replayCache) );
		sp.getPolicyRules().add( new IssueInstantRule(300, 300));
		sp.getPolicyRules().add( new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(signatureTrustEngine));

		sp.getPolicyRules().add( new SAML2HTTPRedirectDeflateSignatureRule(signatureTrustEngine));
		{
			List<KeyInfoProvider> keyInfoProviders = new ArrayList<KeyInfoProvider>();
			keyInfoProviders.add(new DSAKeyValueProvider());
			keyInfoProviders.add(new RSAKeyValueProvider());
			keyInfoProviders.add(new InlineX509DataProvider());
			KeyInfoCredentialResolver keyInfoCredResolver = new BasicProviderKeyInfoCredentialResolver(keyInfoProviders);
			sp.getPolicyRules().add( new SAML2HTTPPostSimpleSignRule(signatureTrustEngine, parserPool, keyInfoCredResolver));
		}
		sp.getPolicyRules().add( new ShibbolethClientCertAuthRule(credentialTrustEngine));
		sp.getPolicyRules().add( new MandatoryIssuerRule());
		sp.getPolicyRules().add( new MandatoryAuthenticatedMessageRule());
		aqc.setSecurityPolicy(sp);
		return pc;
	}

	public AbstractSAMLProfileConfiguration createSaml2SsoProfile(FederationMember federationMember,
			SamlProfileEnumeration type, SAMLProfile profile) {
		AbstractSAMLProfileConfiguration pc;
		edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration sso = 
				new edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration();
		pc = sso;
		if (profile.getOutboundArtifactType() != null) {
		    byte[] artifactTypeBytes = DatatypeHelper.intToByteArray(Integer.parseInt(profile.getOutboundArtifactType()));
		    byte[] trimmedArtifactTypeBytes = { artifactTypeBytes[2], artifactTypeBytes[3] };
		    sso.setOutboundArtifactType( trimmedArtifactTypeBytes);
		} else {
			sso.setOutboundArtifactType(null);
		}
		if (profile.getAssertionLifetime() != null) {
		    long lifetime = SpringConfigurationUtils.parseDurationToMillis("'assertionLifetime' on profile configuration of type " + type + " of " + federationMember,
		            profile.getAssertionLifetime(), 0);
		    sso.setAssertionLifetime(lifetime);
		}
		sso.setProxyCount(profile.getAssertionProxyCount() == null? 0: profile.getAssertionProxyCount().intValue());
		sso.setEncryptNameID(parseCrypto(profile.getEncryptNameIds(), CryptoOperationRequirementLevel.never));
		sso.setEncryptAssertion(parseCrypto(profile.getEncryptAssertions(), CryptoOperationRequirementLevel.never));
		if (profile.getMaximumSPSessionLifetime() != null) {
		    long lifetime = SpringConfigurationUtils.parseDurationToMillis("'maximumSPSessionLifetime' on profile configuration of type " + type + " of " + federationMember,
		            profile.getMaximumSPSessionLifetime(), 300); // 5 minutes
		    sso.setMaximumSPSessionLifetime(lifetime);
		}
		sso.setIncludeAttributeStatement(profile.getIncludeAttributeStatement() == null? false: profile.getIncludeAttributeStatement().booleanValue());
		sso.setAttributeAuthority(saml2AttributeAuthority);

		ShibbolethSecurityPolicy sp = new ShibbolethSecurityPolicy("shibboleth.SAML2SSOSecurityPolicy");
		sp.getPolicyRules().add( new MessageReplayRule(replayCache) );
		sp.getPolicyRules().add( new IssueInstantRule(300, 300));
		sp.getPolicyRules().add( new SAML2AuthnRequestsSignedRule());
		sp.getPolicyRules().add( new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(signatureTrustEngine));

		sp.getPolicyRules().add( new SAML2HTTPRedirectDeflateSignatureRule(signatureTrustEngine));
		{
			List<KeyInfoProvider> keyInfoProviders = new ArrayList<KeyInfoProvider>();
			keyInfoProviders.add(new DSAKeyValueProvider());
			keyInfoProviders.add(new RSAKeyValueProvider());
			keyInfoProviders.add(new InlineX509DataProvider());
			KeyInfoCredentialResolver keyInfoCredResolver = new BasicProviderKeyInfoCredentialResolver(keyInfoProviders);
			sp.getPolicyRules().add( new SAML2HTTPPostSimpleSignRule(signatureTrustEngine, parserPool, keyInfoCredResolver));
		}
		sp.getPolicyRules().add( new MandatoryIssuerRule());
		sso.setSecurityPolicy(sp);
		return pc;
	}

	public AbstractSAMLProfileConfiguration createSaml2SloProfile(FederationMember federationMember,
			SamlProfileEnumeration type, SAMLProfile profile) {
		AbstractSAMLProfileConfiguration pc;
		edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.LogoutRequestConfiguration slo = 
				new edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.LogoutRequestConfiguration();
		pc = slo;
		if (profile.getOutboundArtifactType() != null) {
		    byte[] artifactTypeBytes = DatatypeHelper.intToByteArray(Integer.parseInt(profile.getOutboundArtifactType()));
		    byte[] trimmedArtifactTypeBytes = { artifactTypeBytes[2], artifactTypeBytes[3] };
		    slo.setOutboundArtifactType( trimmedArtifactTypeBytes);
		} else {
			slo.setOutboundArtifactType(null);
		}
		if (profile.getAssertionLifetime() != null) {
		    long lifetime = SpringConfigurationUtils.parseDurationToMillis("'assertionLifetime' on profile configuration of type " + type + " of " + federationMember,
		            profile.getAssertionLifetime(), 0);
		    slo.setAssertionLifetime(lifetime);
		}
		slo.setProxyCount(profile.getAssertionProxyCount() == null? 0: profile.getAssertionProxyCount().intValue());
		slo.setEncryptNameID(parseCrypto(profile.getEncryptNameIds(), CryptoOperationRequirementLevel.never));
		slo.setEncryptAssertion(parseCrypto(profile.getEncryptAssertions(), CryptoOperationRequirementLevel.never));
		slo.setAttributeAuthority(saml2AttributeAuthority);

		ShibbolethSecurityPolicy sp = new ShibbolethSecurityPolicy("shibboleth.SAML2SSOSecurityPolicy");
		sp.getPolicyRules().add( new MessageReplayRule(replayCache) );
		sp.getPolicyRules().add( new IssueInstantRule(300, 300));
		sp.getPolicyRules().add( new SAMLProtocolMessageXMLSignatureSecurityPolicyRule(signatureTrustEngine));

		sp.getPolicyRules().add( new SAML2HTTPRedirectDeflateSignatureRule(signatureTrustEngine));
		{
			List<KeyInfoProvider> keyInfoProviders = new ArrayList<KeyInfoProvider>();
			keyInfoProviders.add(new DSAKeyValueProvider());
			keyInfoProviders.add(new RSAKeyValueProvider());
			keyInfoProviders.add(new InlineX509DataProvider());
			KeyInfoCredentialResolver keyInfoCredResolver = new BasicProviderKeyInfoCredentialResolver(keyInfoProviders);
			sp.getPolicyRules().add( new SAML2HTTPPostSimpleSignRule(signatureTrustEngine, parserPool, keyInfoCredResolver));
		}
        sp.getPolicyRules().add( new ShibbolethClientCertAuthRule(credentialTrustEngine));
        sp.getPolicyRules().add( new MandatoryIssuerRule());
		slo.setSecurityPolicy(sp);
		return pc;
	}

	private CryptoOperationRequirementLevel parseCrypto(SAMLRequirementEnumeration encryptNameIds, CryptoOperationRequirementLevel defaultValue) {
		if (encryptNameIds == SAMLRequirementEnumeration.ALWAYS)
			return CryptoOperationRequirementLevel.always;
		else if (encryptNameIds == SAMLRequirementEnumeration.CONDITIONAL)
			return CryptoOperationRequirementLevel.conditional;
		else if (encryptNameIds == SAMLRequirementEnumeration.NEVER)
			return CryptoOperationRequirementLevel.never;
		else
			return defaultValue;
	}


	@Override
	public RelyingPartyConfiguration getDefaultRelyingPartyConfiguration() {
		IdpConfig c;
		try {
			c = IdpConfig.getConfig();
			RelyingPartyConfiguration rp2 = getRelyingPartyConfiguration(c.getFederationMember().getPublicId());
			return rp2;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		
	}

	@Override
	public RelyingPartyConfiguration getRelyingPartyConfiguration(String relyingPartyEntityID) {
		try {
			IdpConfig c = IdpConfig.getConfig();
			FederationService federationService = new RemoteServiceLocator().getFederacioService();
			FederationMember fm = federationService.findFederationMemberByPublicId(relyingPartyEntityID);
			if (fm == null || 
					fm.getVirtualIdentityProviderPublicId() == null ||
					fm.getVirtualIdentityProviderPublicId().isEmpty())
				return getRelyingPartyConfiguration(c, c.getFederationMember().getPublicId());
			else
				return getRelyingPartyConfiguration(c, fm.getVirtualIdentityProviderPublicId().iterator().next());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	/* Metadata provider 
	 */
	
    public MetadataProvider getMetadataProvider() {
    	return metadataProvider;
    }
    
    protected void loadContext() throws ServiceException {
    	super.loadContext();
        GenericApplicationContext newServiceContext = new GenericApplicationContext(getApplicationContext());
        newServiceContext.setDisplayName("ApplicationContext:" + getId());
        Lock writeLock = getReadWriteLock().writeLock();
        writeLock.lock();
        try {
            newServiceContext.refresh();
            onNewContextCreated(newServiceContext);
            setInitialized(true);
        } catch (Throwable e) {
            // Here we catch all the other exceptions thrown by Spring when it starts up the context
            setInitialized(false);
            Throwable rootCause = e;
            while (rootCause.getCause() != null) {
                rootCause = rootCause.getCause();
            }
            log.error("Configuration was not loaded for " + getId()
                    + " service, error creating components.  The root cause of this error was: " +
                    rootCause.getClass().getCanonicalName() + ": " + rootCause.getMessage());
            log.trace("Full stacktrace is: ", e);
            throw new ServiceException("Configuration was not loaded for " + getId()
                    + " service, error creating components.", rootCause);
        }finally{
            writeLock.unlock();
        }
    }

}
