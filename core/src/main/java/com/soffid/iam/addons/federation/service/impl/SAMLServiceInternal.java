package com.soffid.iam.addons.federation.service.impl;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

import javax.crypto.SecretKey;
import javax.validation.constraints.Null;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.assertion.ValidationResult;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.assertion.ConditionValidator;
import org.opensaml.saml.saml2.assertion.SAML20AssertionValidator;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.assertion.StatementValidator;
import org.opensaml.saml.saml2.assertion.SubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.AudienceRestrictionConditionValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyName;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.X509SubjectName;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.KeyNameBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.impl.X509SubjectNameBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.addons.federation.model.FederationMemberEntityDao;
import com.soffid.iam.addons.federation.model.IdentityProviderEntity;
import com.soffid.iam.addons.federation.model.ServiceProviderEntity;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.DataType;
import com.soffid.iam.api.MetadataScope;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.PasswordDomain;
import com.soffid.iam.api.PasswordPolicy;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserData;
import com.soffid.iam.api.UserType;
import com.soffid.iam.model.SamlRequestEntity;
import com.soffid.iam.model.SamlRequestEntityDao;
import com.soffid.iam.service.AccountService;
import com.soffid.iam.service.AdditionalDataService;
import com.soffid.iam.service.ConfigurationService;
import com.soffid.iam.service.DispatcherService;
import com.soffid.iam.service.DomainService;
import com.soffid.iam.service.UserService;
import com.soffid.iam.service.UserDomainService;
import com.soffid.iam.service.saml.CustomSubjectConfirmationValidator;
import com.soffid.iam.service.saml.SAML20ResponseValidator;
import com.soffid.iam.ssl.SeyconKeyStore;

import bsh.EvalError;
import bsh.Interpreter;
import es.caib.seycon.ng.comu.AccountType;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

public class SAMLServiceInternal {
	private static final String EXTERNAL_SAML_PASSWORD_DOMAIN = "EXTERNAL-SAML";
	private static final String ES_CAIB_SEYCON_IDP_AGENT_IDP_AGENT = "es.caib.seycon.idp.agent.IDPAgent";
	Log log = LogFactory.getLog(getClass());
	
	public SAMLServiceInternal () throws InitializationException {
		InitializationService.initialize();
		builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
	}

	private ConfigurationService configurationService;
	private FederationMemberEntityDao federationMemberEntityDao;
	private UserService userService;
	private AdditionalDataService additionalData;
	private UserDomainService userDomainService;
	private DispatcherService dispatcherService;
	private AccountService accountService;
	
	public void setConfigurationService(ConfigurationService configurationService) {
		this.configurationService = configurationService;
		
	}

	public void setFederationMemberEntityDao(FederationMemberEntityDao federationMemberEntityDao) {
		this.federationMemberEntityDao = federationMemberEntityDao;
		
	}

	
	public SamlValidationResults authenticate(String serviceProviderName, String protocol, Map<String, String> response,
			boolean autoProvision) throws Exception {
		String samlResponse = response.get("SAMLResponse");
		
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(
					new ByteArrayInputStream(Base64.decode(samlResponse))
				);

		// Get the marshaller factory
		UnmarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
		 
		// Get the Subject marshaller
		Unmarshaller marshaller = marshallerFactory.getUnmarshaller(doc.getDocumentElement());
		 
		// Marshall the Subject
		Response saml2Response = (Response) marshaller.unmarshall(doc.getDocumentElement());
		String identityProvider = saml2Response.getIssuer().getValue();

		if (! validateResponse(identityProvider, serviceProviderName, saml2Response))
			return null;

		String originalrequest = saml2Response.getInResponseTo();
		SamlRequestEntity requestEntity = samlRequestEntityDao.findByExternalId(originalrequest);
		if (requestEntity == null)
		{
			log.info("Received authentication response for unknown request "+originalrequest);
			return null;
		}
		if (requestEntity.isFinished() == true)
		{
			log.info("Received authentication response for already served request "+originalrequest);
			return null;
		}

		for ( EncryptedAssertion encryptedAssertion: saml2Response.getEncryptedAssertions())
		{
			Assertion assertion = decrypt (serviceProviderName,encryptedAssertion);
			if (validateAssertion(identityProvider, serviceProviderName, assertion))
			{
				return createAuthenticationRecord(serviceProviderName, requestEntity, assertion, autoProvision);
			}
		}
		
		for ( Assertion assertion: saml2Response.getAssertions())
		{
			if (validateAssertion(identityProvider, serviceProviderName, assertion))
			{
				return createAuthenticationRecord(serviceProviderName, requestEntity, assertion, autoProvision);
			}
		}
		
		
		SamlValidationResults result = new SamlValidationResults();
		result.setValid(false);
		return result ;
	}

	private SamlValidationResults createAuthenticationRecord(String hostName, SamlRequestEntity requestEntity, Assertion assertion,
			boolean provision) throws InternalErrorException {
		Subject subject = assertion.getSubject();
		if (subject == null)
		{
			log.info("Assertion does not contain subject information");
			return null;
		}
		
		NameID nameID = subject.getNameID();
		if (nameID == null)
		{
			log.info("Assertion does not contain nameID information");
			return null;
		}
		
		SamlValidationResults result = new SamlValidationResults();
		result.setValid(false);
		if (nameID.getFormat().equals(NameID.PERSISTENT) ||
				nameID.getFormat().equals(NameID.TRANSIENT) ||
				nameID.getFormat().equals(NameID.UNSPECIFIED) ||
				nameID.getFormat().equals(NameID.EMAIL))
		{
			String user = nameID.getValue();
			result.setValid(true);
			result.setPrincipalName(user);
			for (AttributeStatement attStmt: assertion.getAttributeStatements())
			{
				for (Attribute att: attStmt.getAttributes())
				{
					List<String> values = new LinkedList<String>();
					for (XMLObject value: att.getAttributeValues())
					{
						values.add(value.getDOM().getTextContent());
					}
					if (att.getName() != null)
						result.getAttributes().put( att.getName(),values);
					if (att.getFriendlyName() != null)
						result.getAttributes().put( att.getFriendlyName(),values);
				}
			}
		}
		log.info("Cannot get user name. Format "+nameID.getFormat()+" not supported");

		
		StringBuffer sb = new StringBuffer();
		SecureRandom sr = new SecureRandom();
		for (int i = 0; i < 180; i++)
		{
			int random = sr.nextInt(64);
			if (random < 26)
				sb.append((char) ('A'+random));
			else if (random < 52)
				sb.append((char) ('a'+random-26));
			else if (random < 62)
				sb.append((char) ('0'+random-52));
			else if (random < 63)
				sb.append('+');
			else
				sb.append('/');
		}
		
		requestEntity.setKey(sb.toString());

		result.setUser( searchUser (assertion, result, provision )  );
		if (result.getUser() != null)
			requestEntity.setUser( result.getUser().getUserName() );
		requestEntity.setFinished(true);
		samlRequestEntityDao.update(requestEntity);

		return result;
	}

	private User searchUser(Assertion assertion, SamlValidationResults result, boolean provision) throws InternalErrorException {
		String issuer = assertion.getIssuer().getValue();

		com.soffid.iam.api.System dispatcher = createSamlDispatcher(issuer);
		Account account = accountService.findAccount( result.getPrincipalName() , dispatcher.getName());
		if (account != null)
		{
			if (account.getType().equals(AccountType.USER) && account.getOwnerUsers().size() == 1)
			{
				return account.getOwnerUsers().iterator().next();
			}
			if ( ! account.getType().equals(AccountType.IGNORED))
				throw new InternalErrorException( String.format("Account %s at system %s is reserved", 
						result.getPrincipalName(),
						dispatcher.getName()));
		}
		
		if (provision)
		{
			User u = new User();
			u.setActive(true);
			u.setUserName(issuer + "#" +result.getPrincipalName());
			u.setFirstName( toSingleString( result, "urn:oid:2.5.4.42", "givenName") );
			u.setLastName ( toSingleString( result, "urn:oid:2.5.4.4", "surName")) ;
			u.setUserType("E");
			u.setPrimaryGroup("world");
			u.setComments(String.format("Autoprovisioned from %s identity provider", issuer));
			u.setCreatedByUser(u.getUserName());
			u.setCreatedDate(Calendar.getInstance());
			u.setHomeServer("null");
			u.setProfileServer("null");
			u.setMailServer("null");
			Map<String,Object> attributes = new HashMap<String, Object>();
			for (FederationMemberEntity fm: federationMemberEntityDao.findFMByPublicId(issuer))
			{
				if (fm instanceof IdentityProviderEntity)
				{
					try {
						Interpreter interpreter = new Interpreter();
						interpreter.set("user", u); //$NON-NLS-1$
						interpreter.set("attributes", attributes); //$NON-NLS-1$
						interpreter.set("serviceLocator", ServiceLocator.instance()); //$NON-NLS-1$
						
						Object r = interpreter.eval( "" );
						if (Boolean.FALSE.equals(r))
							return null;
					} catch (EvalError e) {
						throw new InternalErrorException(String.format("Error evaluating provisioning script for identity provider %s", issuer),
								e);
					}

				}
			}
			u = userService.create(u);
			for (String att: attributes.keySet())
			{
				Collection<DataType> md = additionalData.findDataTypesByScopeAndName(MetadataScope.USER, att);
				Object v = attributes.get(att);
				if (md != null && ! md.isEmpty() && v != null)
				{
					UserData data = new UserData();
					data.setAttribute(att);
					if ( v instanceof Calendar )
					{
						data.setDateValue( (Calendar) v );
					}
					else if ( v instanceof Date )
					{
						Calendar c = Calendar.getInstance();
						c.setTime( (Date) v );
						data.setDateValue(c);
					}
					else
					{
						data.setValue(v.toString());
					}
					data.setUser(u.getUserName());
					additionalData.create(data);
				}
			}
		}
		return null;
	}

	private String toSingleString(SamlValidationResults result, String oid, String friendlyName) {
		String s = toSingleString(result.getAttributes().get(oid));
		if ( s == null)
			s = toSingleString(result.getAttributes().get(friendlyName));
		return s;
	}

	private String toSingleString(List<String> set) {
		if (set == null || set.isEmpty())
			return null;
		else
		{
			String r = null;
			for ( String s: set)
			{
				if (r == null)
					r = s;
				else
					r = r + " " + s;
			}
			return r;
		}
	}

	private Assertion decrypt(String serviceProvider, EncryptedAssertion encryptedAssertion) throws Exception {		
		X509Certificate cert = (X509Certificate) getCertificateChain(serviceProvider).get(0);
		PrivateKey privateKey = getPrivateKey(serviceProvider).getPrivate();

        KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(
        		new BasicCredential(cert.getPublicKey(), privateKey));

	    org.opensaml.xmlsec.encryption.EncryptedKey key = encryptedAssertion.getEncryptedData().
	                getKeyInfo().getEncryptedKeys().get(0);
	    
        Decrypter decrypter = new Decrypter(null, keyResolver, null);
	    SecretKey dkey = (SecretKey) decrypter.decryptKey(key, encryptedAssertion.getEncryptedData().
	                getEncryptionMethod().getAlgorithm());
	    
        Credential shared = new BasicCredential(dkey);
        
	    decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(shared), null, null);
	    decrypter.setRootInNewDocument(true);
	    return decrypter.decrypt(encryptedAssertion);
	}

	private XMLObjectBuilderFactory builderFactory = null;
	private SamlRequestEntityDao samlRequestEntityDao;

	public SamlRequest generateSamlRequest(String serviceProvider, String identityProvider, long sessionSeconds) throws InternalErrorException {
		try {
			RandomIdentifierGenerationStrategy idGenerator = new RandomIdentifierGenerationStrategy();
			// Get the assertion builder based on the assertion element name
			SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			 
			EntityDescriptor idp = getIdpMetadata(identityProvider);
			if (idp == null)
				throw new InternalErrorException(String.format("Unable to find Identity Provider metadata"));
			IDPSSODescriptor idpssoDescriptor = idp.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);

			EntityDescriptor sp = getSpMetadata(identityProvider);
			
			// Create the assertion
			AuthnRequest req = builder.buildObject( );
			
			String newID = idGenerator.generateIdentifier();
			
			SamlRequest r = new SamlRequest();
			r.setParameters(new HashMap<String, String>());
			for (SingleSignOnService sss : idpssoDescriptor.getSingleSignOnServices()) {
				if (sss.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI)) {
					r.setMethod(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
					r.setUrl(sss.getLocation());
					req.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
					req.setDestination(sss.getLocation());
					break;
				}
				if (sss.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI)) {
					r.setMethod(SAMLConstants.SAML2_POST_BINDING_URI);
					r.setUrl(sss.getLocation());
					req.setDestination(sss.getLocation());
					req.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
					break;
				}
			}
			if (r.getUrl() == null)
				throw new InternalErrorException(String.format("Unable to find a suitable endpoint for IdP %s"), idp.getEntityID());

			SPSSODescriptor spsso = sp.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
			if (spsso == null)
				throw new InternalErrorException("Unable to find SP SSO Profile "+serviceProvider);
			boolean found = false;
			for ( AssertionConsumerService acs : spsso.getAssertionConsumerServices())
			{
				if (acs.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI))
				{
					req.setAssertionConsumerServiceURL(acs.getLocation());
					req.setAssertionConsumerServiceIndex(acs.getIndex());
				}
			}
			if (req.getAssertionConsumerServiceURL() == null)
				throw new InternalErrorException(String.format("Unable to find a HTPP-Post bindinf for SP %s"), serviceProvider);

			req.setForceAuthn(false);
			req.setID(newID);
			req.setIssueInstant(new DateTime ());
			Issuer issuer = ( (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
			issuer.setValue( serviceProvider );
			
			req.setIssuer( issuer );
			
			Element xml = sign (serviceProvider, builderFactory, req);
			
			String xmlString = generateString(xml);
			
			r.getParameters().put("RelayState", newID);
			r.getParameters().put("SAMLRequest", Base64.encodeBytes(xmlString.getBytes("UTF-8")));

			
			SamlRequestEntity reqEntity = samlRequestEntityDao.newSamlRequestEntity();
			reqEntity.setHostName(serviceProvider);
			reqEntity.setDate(new Date());
			reqEntity.setExpirationDate(new Date(System.currentTimeMillis()+sessionSeconds * 1000L));
			reqEntity.setExternalId(newID);
			reqEntity.setFinished(false);
			samlRequestEntityDao.create(reqEntity);

			return r;
		} catch (Exception e) {
			if (e instanceof InternalErrorException)
				throw (InternalErrorException) e;
			else
				throw new InternalErrorException(e.getMessage(), e);
		}
	}
	
	private String generateString(Element xml)
			throws TransformerConfigurationException,
			TransformerFactoryConfigurationError, TransformerException {
		Transformer transformer = TransformerFactory.newInstance().newTransformer();

		StreamResult result = new StreamResult(new StringWriter());
		DOMSource source = new DOMSource(xml);
		transformer.transform(source, result);

		String xmlString = result.getWriter().toString();
		return xmlString;
	}

	private Element sign(String serviceProvider, XMLObjectBuilderFactory builderFactory, AuthnRequest req) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException, UnrecoverableKeyException, MarshallingException, org.opensaml.xmlsec.signature.support.SignatureException, UnmarshallingException, SAXException, ParserConfigurationException {
		List<Certificate> certs = getCertificateChain(serviceProvider);
		if (certs == null || certs.isEmpty())
			throw new InternalErrorException ("Cannot find certificate chain for "+serviceProvider);
		
		KeyPair pk = getPrivateKey(serviceProvider);
		if (pk == null)
			throw new InternalErrorException ("Cannot find private key for "+serviceProvider);

		Credential cred = new BasicX509Credential(
				(X509Certificate) certs.get(0), 
				pk.getPrivate());
		XMLObjectBuilder<Signature> signatureBuilder = builderFactory.getBuilderOrThrow(Signature.DEFAULT_ELEMENT_NAME);
		Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setSigningCredential(cred);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
		signature.setKeyInfo(getKeyInfo(serviceProvider));
		req.setSignature(signature);
		
		// Get the marshaller factory
		MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(req);
		Element element = marshaller.marshall(req);
		Signer.signObject(signature);
		
		req = (AuthnRequest) unmarshallerFactory.getUnmarshaller(req.getDOM()).unmarshall(req.getDOM());
		return marshallerFactory.getMarshaller(req).marshall(req);

	}

	private EntityDescriptor getIdpMetadata(String identityProvider) throws UnmarshallingException, SAXException, IOException, ParserConfigurationException {
		for (FederationMemberEntity fm :federationMemberEntityDao.findFMByPublicId(identityProvider))
		{
			byte metadata [] = fm.getMetadades();

			if (metadata != null)
			{
				try {
					DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
					DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
					Document doc = dBuilder.parse( new ByteArrayInputStream(metadata));
	 
					UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
					
					XMLObject ed = unmarshallerFactory.getUnmarshaller(doc.getDocumentElement()).unmarshall(doc.getDocumentElement());
					if (ed instanceof EntityDescriptor &&
							((EntityDescriptor) ed).getIDPSSODescriptor(SAMLConstants.SAML20P_NS) != null)
						return (EntityDescriptor) ed;
				} catch (UnmarshallingException e) {
					log.info("Error unmarshalling "+fm.getName()+" metadata");
				} catch (SAXException e) {
					log.info("Error parsing "+fm.getName()+" metadata");
				}
			}
		}
		return null;
	}

	private EntityDescriptor getSpMetadata(String identityProvider) throws IOException, ParserConfigurationException, InternalErrorException {
		for (FederationMemberEntity fm :federationMemberEntityDao.findFMByPublicId(identityProvider))
		{
			byte metadata [] = fm.getMetadades();

			if (metadata != null)
			{
				try {
					DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
					DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
					Document doc = dBuilder.parse( new ByteArrayInputStream(metadata));
	 
					UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
					
					XMLObject ed = unmarshallerFactory.getUnmarshaller(doc.getDocumentElement()).unmarshall(doc.getDocumentElement());
					if (ed instanceof EntityDescriptor &&
							((EntityDescriptor) ed).getSPSSODescriptor(SAMLConstants.SAML20P_NS) != null)
						return (EntityDescriptor) ed;
				} catch (UnmarshallingException e) {
					log.info("Error unmarshalling "+fm.getName()+" metadata");
				} catch (SAXException e) {
					log.info("Error parsing "+fm.getName()+" metadata");
				}
			}
		}
		throw new InternalErrorException("Unable to find metadata for service provider "+identityProvider);
	}

	private KeyPair getPrivateKey(String identityProvider) throws UnmarshallingException, SAXException, IOException, ParserConfigurationException, InternalErrorException {
		for (FederationMemberEntity fm :federationMemberEntityDao.findFMByPublicId(identityProvider))
		{
			if (fm instanceof ServiceProviderEntity)
			{
		        // Now read the private and public key
		        PEMReader pm = new PEMReader( new StringReader(fm.getPrivateKey()));
		        KeyPair kp = (KeyPair) pm.readObject();
		        pm.close();
		        
		        return kp;
			}
		}
		throw new InternalErrorException("Unable to find private key for service provider "+identityProvider);
	}

	private List<Certificate> getCertificateChain(String identityProvider) throws UnmarshallingException, SAXException, IOException, ParserConfigurationException, InternalErrorException {
		for (FederationMemberEntity fm :federationMemberEntityDao.findFMByPublicId(identityProvider))
		{
			if (fm instanceof ServiceProviderEntity)
			{
		        PEMReader pm = new PEMReader( new StringReader(fm.getCertificateChain()));
		        List<Certificate> certs = new LinkedList<Certificate>();
		        do
		        {
		        	Certificate cert = (Certificate) pm.readObject();
		        	if (cert == null)
		        		break;
		        	certs.add(cert);
		        } while (true);
		        pm.close();

		        return certs;
			}
		}
		throw new InternalErrorException("Unable to find certificate chain for service provider "+identityProvider);
	}

	private KeyInfo getKeyInfo(String identityProvider) throws UnmarshallingException, SAXException, IOException, ParserConfigurationException, InternalErrorException {
		EntityDescriptor md = getSpMetadata(identityProvider);
		if (md != null)
		{
			SPSSODescriptor spsso = md.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
			for ( KeyDescriptor kd: spsso.getKeyDescriptors())
			{
				KeyInfo ki = kd.getKeyInfo();
				if (ki != null)
					return ki;
			}
		}
		throw new InternalErrorException("Unable to find key info for service provider "+identityProvider);
	}

	public void setSamlRequestEntityDao(SamlRequestEntityDao samlRequestEntityDao) {
		this.samlRequestEntityDao = samlRequestEntityDao;
	}

    private boolean validateAssertion (String identityProvider, String serviceProvider, Assertion assertion) throws ResolverException, InternalErrorException, ComponentInitializationException, AssertionValidationException, CertificateException, UnmarshallingException, SAXException, IOException, ParserConfigurationException
    {
    	SAML20AssertionValidator validator = getValidator(identityProvider, serviceProvider);
    	
    	HashMap<String, Object> params = new HashMap<String, Object>();
    	params.put(
                SAML2AssertionValidationParameters.COND_VALID_AUDIENCES, 
                	Collections.singleton(serviceProvider));
    	
    	EntityDescriptor md = getSpMetadata(serviceProvider);
		SPSSODescriptor spsso = md.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
    	Set<String> set = new HashSet<String>();
		for ( AssertionConsumerService acs: spsso.getAssertionConsumerServices())
		{
			set.add(acs.getBinding());
		}
    	params.put (SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, set);

    	org.opensaml.saml.common.assertion.ValidationContext ctx = new ValidationContext(params);

		ValidationResult result = validator.validate(assertion, ctx);
		if (result != ValidationResult.VALID)
			log.info("Error validating SAML message: "+ctx.getValidationFailureMessage());
		
		if ( ! validDate (assertion.getIssueInstant()))
			return false;

		return result == ValidationResult.VALID ;
    	
    }

	private boolean validDate(DateTime issueInstant) {
		if (issueInstant == null)
		{
			log.info("Error validatig assertion: issueInstant is null");
			return false;
		}
		Calendar c = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
		c.set(Calendar.YEAR, issueInstant.getYear());
		c.set(Calendar.MONTH, issueInstant.getMonthOfYear()-1);
		c.set(Calendar.DAY_OF_MONTH, issueInstant.getDayOfMonth());
		c.set(Calendar.HOUR_OF_DAY, issueInstant.getHourOfDay());
		c.set(Calendar.MINUTE, issueInstant.getMinuteOfHour());
		c.set(Calendar.SECOND, issueInstant.getSecondOfMinute());
		c.set(Calendar.MILLISECOND, issueInstant.getSecondOfMinute());
		
		// Test if issue instant is five minutes after now (allow 5 minutes time skew)
		Calendar now = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
		now.add(Calendar.MINUTE, 5);
		if (c.after( now ))
		{
			log.info("Error validatig assertion: issueInstant is after current instant");
			return false;
		}
		
		// Test if issue instant is ten minutes before now (allow 5 minutes for assertion to travel plus 5 minutes time skew)
		now = new GregorianCalendar();
		now.add(Calendar.MINUTE, -10);
		if (c.before( now ))
		{
			log.info("Error validatig assertion: issueInstant is more than ten minutes old");
			return false;
		}

		return true;
	}

	private SAML20AssertionValidator getValidator(String identityProvider, String serviceProvider) throws ResolverException, InternalErrorException, ComponentInitializationException, CertificateException, UnmarshallingException, SAXException, IOException, ParserConfigurationException {
		EntityDescriptor md = getIdpMetadata(identityProvider);

		List<ConditionValidator> conditionValidators = new LinkedList<ConditionValidator>();
		conditionValidators.add( new AudienceRestrictionConditionValidator() );
		
    	List<SubjectConfirmationValidator> subjectConfirmationValidators = new LinkedList<SubjectConfirmationValidator>();
    	List<StatementValidator> statementValidators = new LinkedList<StatementValidator>();
    	Set<Credential> trustedCredentials = new HashSet<Credential>();
    	
    	IDPSSODescriptor idp = md.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    	if (idp != null)
    	{
    		for (KeyDescriptor kd: idp.getKeyDescriptors())
    		{
    			if (kd.getUse() == UsageType.SIGNING || 
    					kd.getUse() == UsageType.UNSPECIFIED)
    			{
	    			for (X509Data x509data: kd.getKeyInfo().getX509Datas())
	    			{
						for (org.opensaml.xmlsec.signature.X509Certificate certElement: x509data.getX509Certificates())
	    				{
							CertificateFactory factory = CertificateFactory.getInstance("X.509");
							X509Certificate cert = (X509Certificate) 
								factory.generateCertificate( new ByteArrayInputStream(
									Base64.decode(certElement.getValue())
								));
	    					BasicX509Credential cred = new BasicX509Credential(cert);
	    					cred.setEntityId(md.getEntityID());
	    					cred.setUsageType(kd.getUse());
							trustedCredentials.add( cred);
	    				}
	    			}
    			}
    		}
    	}
    	CollectionCredentialResolver credentialResolver  = new CollectionCredentialResolver(trustedCredentials);
    	SignatureTrustEngine signatureTrustEngine;
    	SignaturePrevalidator signaturePrevalidator;
    	  
		subjectConfirmationValidators.add( new CustomSubjectConfirmationValidator());
    	signatureTrustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
    	signaturePrevalidator = new SAMLSignatureProfileValidator();
    	
    	return new SAML20AssertionValidator(conditionValidators, subjectConfirmationValidators, statementValidators, signatureTrustEngine, signaturePrevalidator);
	}

    private boolean validateResponse (String serviceProvider, String identityProvider, Response assertion) throws ResolverException, InternalErrorException, ComponentInitializationException, AssertionValidationException, CertificateException, UnmarshallingException, SAXException, IOException, ParserConfigurationException
    {
    	SAML20ResponseValidator validator = getResponseValidator(identityProvider);
    	
    	org.opensaml.saml.common.assertion.ValidationContext ctx = new ValidationContext();
    	
		ValidationResult result = validator.validate(assertion, ctx);
		if (result != ValidationResult.VALID)
			log.info("Error validating SAML message: "+ctx.getValidationFailureMessage());
		
		if ( ! validDate (assertion.getIssueInstant()))
			return false;
		
		if ( assertion.getStatus() == null || assertion.getStatus().getStatusCode() == null)
		{
			log.info("Response does not contain status");
			return false;
		}
		
		if ( ! assertion.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS))
		{
			log.info("Authentication failed: "+assertion.getStatus().getStatusCode().getValue());
			return false;
		}

    	return result == ValidationResult.VALID ;
    	
    }

    private SAML20ResponseValidator getResponseValidator(String identityProvider) throws ResolverException, InternalErrorException, ComponentInitializationException, CertificateException, UnmarshallingException, SAXException, IOException, ParserConfigurationException {
		EntityDescriptor md = getIdpMetadata(identityProvider);

		List<ConditionValidator> conditionValidators = new LinkedList<ConditionValidator>();
    	List<SubjectConfirmationValidator> subjectConfirmationValidators = new LinkedList<SubjectConfirmationValidator>();
    	List<StatementValidator> statementValidators = new LinkedList<StatementValidator>();
    	Set<Credential> trustedCredentials = new HashSet<Credential>();
    	
    	IDPSSODescriptor idp = md.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    	if (idp != null)
    	{
    		for (KeyDescriptor kd: idp.getKeyDescriptors())
    		{
    			if (kd.getUse() == UsageType.SIGNING || 
    					kd.getUse() == UsageType.UNSPECIFIED)
    			{
	    			for (X509Data x509data: kd.getKeyInfo().getX509Datas())
	    			{
						for (org.opensaml.xmlsec.signature.X509Certificate certElement: x509data.getX509Certificates())
	    				{
							CertificateFactory factory = CertificateFactory.getInstance("X.509");
							X509Certificate cert = (X509Certificate) 
								factory.generateCertificate( new ByteArrayInputStream(
									Base64.decode(certElement.getValue())
								));
	    					BasicX509Credential cred = new BasicX509Credential(cert);
	    					cred.setEntityId(md.getEntityID());
	    					cred.setUsageType(kd.getUse());
							trustedCredentials.add( cred);
	    				}
	    			}
    			}
    		}
    	}
    	CollectionCredentialResolver credentialResolver  = new CollectionCredentialResolver(trustedCredentials);
    	SignatureTrustEngine signatureTrustEngine;
    	SignaturePrevalidator signaturePrevalidator;
    	  
    	subjectConfirmationValidators.add(new CustomSubjectConfirmationValidator());
    	signatureTrustEngine = new ExplicitKeySignatureTrustEngine(credentialResolver, DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
    	signaturePrevalidator = new SAMLSignatureProfileValidator();

    	return new SAML20ResponseValidator(conditionValidators, subjectConfirmationValidators, statementValidators, signatureTrustEngine, signaturePrevalidator);
	}

	public SamlValidationResults validateSessionCookie(String sessionCookie) throws InternalErrorException {
		String[] split = sessionCookie.split(":");
		if (split.length != 2)
			throw new InternalErrorException("Invalid cookie");
		SamlRequestEntity entity = samlRequestEntityDao.findByExternalId(split[0]);
		SamlValidationResults r = new SamlValidationResults();
		if (entity == null || entity.getExpirationDate() == null ||
				entity.getExpirationDate().before(new Date()) ||
				! entity.getKey().equals(split[1]))
		{
			r.setValid(false);
			return r;
		}
		
		r.setValid(true);
		r.setUser( userService.findUserByUserName( entity.getUser() ) );
		r.setAttributes(new HashMap<String, List<String>>());
		r.setSessionCookie(sessionCookie);
		r.setIdentityProvider(null);
		return r;
	}
	
	private PasswordDomain createExternalPasswordDomain () throws InternalErrorException
	{
		PasswordDomain pd = userDomainService.findPasswordDomainByName(EXTERNAL_SAML_PASSWORD_DOMAIN);
		if ( pd == null )
		{
			pd = new PasswordDomain();
			pd.setCode(EXTERNAL_SAML_PASSWORD_DOMAIN);
			pd.setDescription("External SAML systems");
			pd = userDomainService.create(pd);
		}
		for ( UserType ut: userDomainService.findAllUserType())
		{
			PasswordPolicy pp = userDomainService.findPolicyByTypeAndPasswordDomain(ut.getCode(), "EXTERNAL_SAML");
			if (pp == null)
			{
				pp = new PasswordPolicy();
				pp.setAllowPasswordChange(false);
				pp.setAllowPasswordQuery(false);
				pp.setDescription("External SAML accounts");
				pp.setUserType(ut.getCode());
				pp.setMaximumHistorical(0L);
				pp.setMinimumLength(1L);
				pp.setMaximumPeriod(3650L);
				pp.setMaximumPeriodExpired(3650L);
				pp.setType("A");
				userDomainService.create(pp);
			}
		}
		return pd;
	}

	private com.soffid.iam.api.System createSamlDispatcher (String publicId) throws InternalErrorException
	{
		com.soffid.iam.api.System s = findDispatcher(publicId);
		if ( s == null )
		{
			createExternalPasswordDomain();
			s = new com.soffid.iam.api.System();
			s.setName("SAML "+publicId);
			s.setDescription("External IDP "+publicId);
			s.setAuthoritative(false);
			s.setAccessControl(false);
			s.setReadOnly(true);
			s.setClassName(ES_CAIB_SEYCON_IDP_AGENT_IDP_AGENT);
			s.setManualAccountCreation(true);
			s.setParam0(publicId);
			s.setUsersDomain("DEFAULT");
			PasswordDomain pd = createExternalPasswordDomain();
			s.setPasswordsDomain(pd.getCode());
			s.setPasswordsDomainId(pd.getId());
			s = dispatcherService.create(s);
		}
		return s;
	}

	private com.soffid.iam.api.System findDispatcher(String publicId) throws InternalErrorException {
		for (com.soffid.iam.api.System d: dispatcherService.findDispatchersByFilter(null, ES_CAIB_SEYCON_IDP_AGENT_IDP_AGENT, null, null, null, null))
		{
			if (d.getParam0().equals(publicId))
				return d;
		}
		return null;
	}

	public UserService getUserService() {
		return userService;
	}

	public void setUserService(UserService userService) {
		this.userService = userService;
	}

	public UserDomainService getUserDomainService() {
		return userDomainService;
	}

	public void setUserDomainService(UserDomainService userDomainService) {
		this.userDomainService = userDomainService;
	}

	public DispatcherService getDispatcherService() {
		return dispatcherService;
	}

	public void setDispatcherService(DispatcherService dispatcherService) {
		this.dispatcherService = dispatcherService;
	}

	public AccountService getAccountService() {
		return accountService;
	}

	public void setAccountService(AccountService accountService) {
		this.accountService = accountService;
	}

	public ConfigurationService getConfigurationService() {
		return configurationService;
	}

	public FederationMemberEntityDao getFederationMemberEntityDao() {
		return federationMemberEntityDao;
	}

	public SamlRequestEntityDao getSamlRequestEntityDao() {
		return samlRequestEntityDao;
	}

	public AdditionalDataService getAdditionalData() {
		return additionalData;
	}

	public void setAdditionalData(AdditionalDataService additionalData) {
		this.additionalData = additionalData;
	}
}
