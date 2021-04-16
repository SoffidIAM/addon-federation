package com.soffid.iam.addons.federation.service.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
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
import org.opensaml.saml.saml2.core.LogoutRequest;
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
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
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
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.soffid.iam.addons.federation.FederationServiceLocator;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.api.User;
import com.soffid.iam.model.SamlRequestEntity;
import com.soffid.iam.model.SamlRequestEntityDao;
import com.soffid.iam.service.SessionService;
import com.soffid.iam.service.saml.CustomSubjectConfirmationValidator;
import com.soffid.iam.service.saml.SAML20ResponseValidator;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class SAMLServiceInternal extends AbstractFederationService {
	private static final String EXTERNAL_SAML_PASSWORD_DOMAIN = "EXTERNAL-SAML";
	private static final String ES_CAIB_SEYCON_IDP_AGENT_IDP_AGENT = "es.caib.seycon.idp.agent.IDPAgent";
	Log log = LogFactory.getLog(getClass());
	
	public SAMLServiceInternal () throws InitializationException {
		InitializationService.initialize();
		builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
	}

	public SamlValidationResults authenticateSaml(String serviceProviderName, String protocol, Map<String, String> response,
			boolean autoProvision) throws Exception {
		
		log.info("authenticate() - serviceProviderName: "+serviceProviderName);
		log.info("authenticate() - protocol: "+protocol);
		log.info("authenticate() - response: "+response);
		log.info("authenticate() - autoProvision: "+autoProvision);
		
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

		SamlValidationResults result = new SamlValidationResults();
		result.setValid(false);

		if (! validateResponse(identityProvider, serviceProviderName, saml2Response, result))
		{
			return result;
		}

		String originalrequest = saml2Response.getInResponseTo();
		SamlRequestEntity requestEntity = samlRequestEntityDao.findByExternalId(originalrequest);
		log.info("authenticate() - requestEntity: "+requestEntity);
		if (requestEntity == null)
		{
			result.setFailureReason("Received authentication response for unknown request "+originalrequest);
			log.info(result.getFailureReason());
			return result;
		}
		if (requestEntity.isFinished() == true)
		{
			result.setFailureReason("Received authentication response for already served request "+originalrequest);
			log.info(result.getFailureReason());
			return result;
		}

		for ( EncryptedAssertion encryptedAssertion: saml2Response.getEncryptedAssertions())
		{
			Assertion assertion = decrypt (serviceProviderName,encryptedAssertion);
			if (validateAssertion(identityProvider, serviceProviderName, saml2Response, assertion, result))
			{
				log.info("authenticate() - in encryptedAssertion");
				if (assertion.isSigned() || response.isEmpty())
					return createAuthenticationRecord(identityProvider, serviceProviderName, requestEntity, assertion, autoProvision);
				else
					result.setFailureReason("Response or assertion are not signed. Signature is required");
			}
		}
		
		for ( Assertion assertion: saml2Response.getAssertions())
		{
			if (validateAssertion(identityProvider, serviceProviderName, saml2Response, assertion, result))
			{
				log.info("authenticate() - in assertion");
				if (assertion.isSigned() || response.isEmpty())
					return createAuthenticationRecord(identityProvider, serviceProviderName, requestEntity, assertion, autoProvision);
				else
					result.setFailureReason("Response or assertion are not signed. Signatue is required");
			}
		}
		
		return result ;
	}

	private SamlValidationResults createAuthenticationRecord(String identityProvider, String serviceProviderName, SamlRequestEntity requestEntity, Assertion assertion,
			boolean provision) throws Exception {
		
		log.info("createAuthenticationRecord()");
		
		SamlValidationResults result = new SamlValidationResults();
		result.setValid(false);
		Subject subject = assertion.getSubject();
		if (subject == null)
		{
			result.setFailureReason("Assertion does not contain subject information");
			return result;
		}
		log.info("createAuthenticationRecord() - subject: "+subject);
		NameID nameID = subject.getNameID();
		if (nameID == null)
		{
			result.setFailureReason("Assertion does not contain nameID information");
			return result;
		}
		log.info("createAuthenticationRecord() - nameID: "+nameID);
		if (nameID.getFormat() == null || 
				nameID.getFormat().equals(NameID.PERSISTENT) ||
				nameID.getFormat().equals(NameID.TRANSIENT) ||
				nameID.getFormat().equals(NameID.UNSPECIFIED) ||
				nameID.getFormat().equals(NameID.EMAIL))
		{
			String user = nameID.getValue();
			log.info("createAuthenticationRecord() - user: "+user);
			result.setPrincipalName(user);
			result.setValid(true);
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
		else
		{
			result.setFailureReason("Cannot get user name. Format "+nameID.getFormat()+" not supported");
			return result;
		}
		
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
		result.setIdentityProvider(identityProvider);
		result.setUser( searchUser (assertion, result, provision )  );
		if (result.getUser() != null) {
			log.info("createAuthenticationRecord() - requestEntity.setUser("+result.getUser().getUserName()+")");
			requestEntity.setUser( result.getUser().getUserName() );
		}
		
		result.setSessionCookie(requestEntity.getExternalId()+":"+requestEntity.getKey());
		log.info("createAuthenticationRecord() - setSessionCookie(requestEntity.getExternalId()+\":\"+requestEntity.getKey())");
		requestEntity.setFinished(true);
		samlRequestEntityDao.update(requestEntity);
		log.info("createAuthenticationRecord() - samlRequestEntityDao.update");
		result.setValid(true);
		return result;
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
	    Assertion assertion = decrypter.decrypt(encryptedAssertion);

		return assertion;
	}

	protected User searchUser(Assertion assertion, SamlValidationResults result, boolean provision) throws Exception {
		
		log.info("searchUser()");
		
		String issuer = assertion.getIssuer().getValue();

		return findAccountOwner (result.getPrincipalName(), issuer, (Map<String,? extends Object>) result.getAttributes(), provision);
	}


	private XMLObjectBuilderFactory builderFactory = null;
	private SamlRequestEntityDao samlRequestEntityDao;
	private SessionService sessionService;

	public SamlRequest generateSamlRequest(String serviceProvider, String identityProvider, String userName, long sessionSeconds) throws InternalErrorException {
		try {
			// Get the assertion builder based on the assertion element name
			SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			 
			EntityDescriptor idp = getIdpMetadata(identityProvider);
			if (idp == null)
				throw new InternalErrorException(String.format("Unable to find Identity Provider metadata"));
			IDPSSODescriptor idpssoDescriptor = idp.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);

			EntityDescriptor sp = getSpMetadata(serviceProvider);
			
			// Create the assertion
			AuthnRequest req = builder.buildObject( );
			
			String newID = generateRandomId();
			
			SamlRequest r = new SamlRequest();
			r.setParameters(new HashMap<String, String>());
			SPSSODescriptor spsso = sp.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
			if (spsso == null)
				throw new InternalErrorException("Unable to find SP SSO Profile "+serviceProvider);
			boolean found = false;
			for ( AssertionConsumerService acs : spsso.getAssertionConsumerServices())
			{
				if (acs.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI))
				{
					req.setAssertionConsumerServiceURL(acs.getLocation());
				}
			}
			if (req.getAssertionConsumerServiceURL() == null)
				throw new InternalErrorException(String.format("Unable to find a HTTP-Post binding for SP %s"), serviceProvider);

			req.setForceAuthn(false);
			req.setID(newID);
			req.setIssueInstant(new DateTime ());
			Issuer issuer = ( (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
			issuer.setValue( serviceProvider );
			
			req.setIssuer( issuer );

			KeyPair pk = getPrivateKey(serviceProvider);
			if (pk == null)
				throw new InternalErrorException ("Cannot find private key for "+serviceProvider);
			
			for (SingleSignOnService sss : idpssoDescriptor.getSingleSignOnServices()) {
				if (sss.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI) && 
						pk == null) { // Max GET length is usually 8192
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

			if (userName != null) {
	        	userName = FederationServiceLocator.instance().getFederacioService().getLoginHint(identityProvider, userName);
			}
			if (userName != null && ! userName.trim().isEmpty())
			{
				Subject newSubject = ( (SAMLObjectBuilder<Subject>)builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME)).buildObject();
				NameID newNameID = ( (SAMLObjectBuilder<NameID>)builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
				newNameID.setValue(userName);
				if (userName.contains("@") && userName.contains("."))
					newNameID.setFormat(NameID.EMAIL);
				else
					newNameID.setFormat(NameID.PERSISTENT);
				newSubject.setNameID(newNameID);
				req.setSubject(newSubject );
			}

			// Sign again
			Element xml = sign (serviceProvider, builderFactory, req);
			String xmlString = generateString(xml);

			// Encode base 64
			String encodedRequest = Base64.encodeBytes(xmlString.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);
			r.getParameters().put("SAMLRequest", encodedRequest);
			r.getParameters().put("RelayState", newID);


			// Record
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
	
	protected String generateString(Element xml)
			throws TransformerConfigurationException,
			TransformerFactoryConfigurationError, TransformerException {
		Transformer transformer = TransformerFactory.newInstance().newTransformer();

		StreamResult result = new StreamResult(new StringWriter());
		DOMSource source = new DOMSource(xml);
		transformer.transform(source, result);

		String xmlString = result.getWriter().toString();
		return xmlString;
	}


	private boolean isAzure(AuthnRequest req) {
		boolean azure = req.getDestination().startsWith("https://login.microsoftonline.com/");
		log.info("Consumer URL ="+req.getDestination()+" azure workaround="+azure);
		return azure;
	}

	public SamlRequest generateSamlLogout(String serviceProvider, String identityProvider, String userName, boolean forced, boolean backChannel) throws InternalErrorException {
		try {
			// Get the assertion builder based on the assertion element name
			SAMLObjectBuilder<LogoutRequest> builder = (SAMLObjectBuilder<LogoutRequest>) builderFactory.getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME);
			 
			EntityDescriptor idp = getIdpMetadata(identityProvider);
			if (idp == null)
				throw new InternalErrorException(String.format("Unable to find Identity Provider metadata"));
			IDPSSODescriptor idpssoDescriptor = idp.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);

			EntityDescriptor sp = getSpMetadata(serviceProvider);
			
			// Create the assertion
			LogoutRequest req = builder.buildObject( );
			
			String newID = generateRandomId();
			
			SamlRequest r = new SamlRequest();
			r.setParameters(new HashMap<String, String>());
			SPSSODescriptor spsso = sp.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
			if (spsso == null)
				throw new InternalErrorException("Unable to find SP SSO Profile "+serviceProvider);
			boolean found = false;
			req.setID(newID);
			req.setIssueInstant(new DateTime ());
			NameID nameId = ((SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
			nameId.setValue(userName);
			req.setNameID(nameId);

			req.setReason(forced ? "urn:oasis:names:tc:SAML:2.0:logout:udmin": "urn:oasis:names:tc:SAML:2.0:logout:user");
			
			Issuer issuer = ( (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
			issuer.setValue( serviceProvider );
			
			req.setIssuer( issuer );

			
			String encodedRequest = null;
			for (SingleLogoutService sss : idpssoDescriptor.getSingleLogoutServices()) {
				if (sss.getBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI) &&  backChannel) { // Max GET length is usually 8192
					r.setMethod(SAMLConstants.SAML2_SOAP11_BINDING_URI);
					r.setUrl(sss.getLocation());

					encodedRequest = signAndEncode(serviceProvider, req, sss);
					break;
				}
				if (sss.getBinding().equals(SAMLConstants.SAML2_REDIRECT_BINDING_URI) && 
						!backChannel) { // Max GET length is usually 8192
					encodedRequest = signAndEncode(serviceProvider, req, sss);
					if (encodedRequest.length() <= 2000)
					{
						r.setMethod(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
						r.setUrl(sss.getLocation());
						break;
					}
				}
				if (sss.getBinding().equals(SAMLConstants.SAML2_POST_BINDING_URI) && !backChannel) {
					r.setMethod(SAMLConstants.SAML2_POST_BINDING_URI);
					r.setUrl(sss.getLocation());
					encodedRequest = signAndEncode(serviceProvider, req, sss);
					break;
				}
			}
			if (r.getUrl() == null)
				throw new InternalErrorException(String.format("Unable to find a suitable endpoint for IdP %s", idp.getEntityID()));
			
			
			r.getParameters().put("RelayState", newID);
			r.getParameters().put("SAMLRequest", encodedRequest);


			return r;
		} catch (Exception e) {
			if (e instanceof InternalErrorException)
				throw (InternalErrorException) e;
			else
				throw new InternalErrorException(e.getMessage(), e);
		}
	}

	private String signAndEncode(String serviceProvider, LogoutRequest req, SingleLogoutService sss)
			throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
			NoSuchProviderException, SignatureException, IOException, InternalErrorException, UnrecoverableKeyException,
			MarshallingException, org.opensaml.xmlsec.signature.support.SignatureException, UnmarshallingException,
			SAXException, ParserConfigurationException, TransformerConfigurationException,
			TransformerFactoryConfigurationError, TransformerException, UnsupportedEncodingException {
		String encodedRequest;
		req.setDestination( sss.getLocation() );
		Element xml = sign (serviceProvider, builderFactory, req);
		String xmlString = generateString(xml);
		encodedRequest  = Base64.encodeBytes(xmlString.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);
		return encodedRequest;
	}
	
	private String generateLogoutRequest(LogoutRequest req) {
		// TODO Auto-generated method stub
		return null;
	}

	private Element sign(String serviceProvider, XMLObjectBuilderFactory builderFactory, org.opensaml.saml.saml2.core.RequestAbstractType req) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException, UnrecoverableKeyException, MarshallingException, org.opensaml.xmlsec.signature.support.SignatureException, UnmarshallingException, SAXException, ParserConfigurationException {
		// Get the marshaller factory
		MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(req);
		Element element = marshaller.marshall(req);

		// Get certificates
		List<Certificate> certs = getCertificateChain(serviceProvider);
		if (certs == null || certs.isEmpty())
			return element;
		
		KeyPair pk = getPrivateKey(serviceProvider);
		if (pk == null)
			throw new InternalErrorException ("Cannot find private key for "+serviceProvider);

		
		// Sign
		Credential cred = new BasicX509Credential(
				(X509Certificate) certs.get(0), 
				pk.getPrivate());
		XMLObjectBuilder<Signature> signatureBuilder = builderFactory.getBuilderOrThrow(Signature.DEFAULT_ELEMENT_NAME);
		Signature signature = signatureBuilder.buildObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setSigningCredential(cred);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
//		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		KeyInfo keyInfo = getKeyInfo(serviceProvider);
		keyInfo.detach();
		signature.setKeyInfo(keyInfo);
		req.setSignature(signature);
		
		// Marshal again
		marshaller = marshallerFactory.getMarshaller(req);
		element = marshaller.marshall(req);
		
		// Sign
		Signer.signObject(signature);

		// Unmarshall
		UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
		XMLObject req2 = unmarshallerFactory.getUnmarshaller(req.getDOM()).unmarshall(req.getDOM());
		return marshallerFactory.getMarshaller(req).marshall(req2);

	}

	private EntityDescriptor getIdpMetadata(String identityProvider) throws UnmarshallingException, SAXException, IOException, ParserConfigurationException {
		for (FederationMemberEntity fm :federationMemberEntityDao.findFMByPublicId(identityProvider))
		{
			byte metadata [] = fm.getMetadades();

			if (metadata != null)
			{
				try {
					DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
					dbFactory.setNamespaceAware(true);
					dbFactory.setValidating(false);
					DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
					Document doc = dBuilder.parse( new ByteArrayInputStream(metadata));
	 
					UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
					
					XMLObject ed = unmarshallerFactory.getUnmarshaller(EntityDescriptor.ELEMENT_QNAME)
							.unmarshall(doc.getDocumentElement());
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
					dbFactory.setNamespaceAware(true);
					dbFactory.setValidating(false);
					DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
					Document doc = dBuilder.parse( new ByteArrayInputStream(metadata));
	 
					UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
					
					XMLObject ed = unmarshallerFactory.getUnmarshaller(EntityDescriptor.ELEMENT_QNAME)
							.unmarshall(doc.getDocumentElement());

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
			if (fm.getPrivateKey() != null && !fm.getPrivateKey().trim().isEmpty())
			{
				// Now read the private and public key
				PEMParser pemParser = new PEMParser(new StringReader(fm.getPrivateKey()));
				Object object = pemParser.readObject();
			    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
			    KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
				pemParser.close();
				return kp;
			}
		}
		throw new InternalErrorException("Unable to find private key for service provider "+identityProvider);
	}

	private List<Certificate> getCertificateChain(String identityProvider) throws UnmarshallingException, SAXException, IOException, ParserConfigurationException, InternalErrorException {
		java.security.AccessController.doPrivileged(new PrivilegedAction<Object>() {
			public Object run() {
				if (Security.getProvider("BC") == null)
					Security.addProvider(new BouncyCastleProvider());
				return null;
			}
		});
		for (FederationMemberEntity fm :federationMemberEntityDao.findFMByPublicId(identityProvider))
		{
			//String publicCertX509 = null;	
			PEMParser pemParser = new PEMParser(new StringReader(fm.getCertificateChain()));
			JcaX509CertificateConverter converter2 = new JcaX509CertificateConverter().setProvider( "BC" );
	        List<Certificate> certs = new LinkedList<Certificate>();
			do {
				Object object = pemParser.readObject();
				if (object == null) break;
				if (object instanceof X509CertificateHolder)
				{
					try
					{
						X509Certificate cert = converter2.getCertificate((X509CertificateHolder) object); 
						//publicCertX509 = Base64.encodeBytes(cert.getEncoded());
			        	if (cert == null)
			        		break;
			        	certs.add(cert);
			        } catch (CertificateEncodingException e) {
			            Logger log = LoggerFactory.getLogger(getClass ());
			            log.warn("Error decoding certificate for public id "+fm.getName()); //$NON-NLS-1$
			        } catch (CertificateException e) {
			            Logger log = LoggerFactory.getLogger(getClass ());
			            log.warn("Error decoding certificate for public id "+fm.getName()); //$NON-NLS-1$
					}
			        break;
				}
			} while (true);
			pemParser.close();
	        return certs;
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

    private boolean validateAssertion (String identityProvider, String serviceProvider, Response saml2Response, Assertion assertion, SamlValidationResults result2) 
    		throws InternalErrorException, AssertionValidationException, CertificateException, UnmarshallingException, SAXException, IOException, ParserConfigurationException
    {    	
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

    	if (assertion.isSigned())
    	{
	    	SAML20AssertionValidator validator = getValidator(identityProvider, serviceProvider);
			ValidationResult result = validator.validate(assertion, ctx);
			if (result != ValidationResult.VALID)
			{
				result2.setFailureReason(ctx.getValidationFailureMessage());
				log.info("Error validating SAML message: "+ctx.getValidationFailureMessage());
			}
    	}
		
		if ( ! validDate (assertion.getIssueInstant(), result2))
			return false;

		return true ;
    	
    }

	private boolean validDate(DateTime issueInstant, SamlValidationResults result2) {
		if (issueInstant == null)
		{
			result2.setFailureReason("Error validatig assertion: issueInstant is missing");
			log.info(result2.getFailureReason());
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
			result2.setFailureReason("Error validatig assertion: issueInstant is after current instant");
			log.info(result2.getFailureReason());
			return false;
		}
		
		// Test if issue instant is ten minutes before now (allow 5 minutes for assertion to travel plus 5 minutes time skew)
		now = new GregorianCalendar();
		now.add(Calendar.MINUTE, -10);
		if (c.before( now ))
		{
			result2.setFailureReason("Error validatig assertion: issueInstant is more than ten minutes old");
			log.info(result2.getFailureReason());
			return false;
		}

		return true;
	}

	private SAML20AssertionValidator getValidator(String identityProvider, String serviceProvider) 
			throws InternalErrorException, CertificateException, UnmarshallingException, SAXException, IOException, ParserConfigurationException 
	{
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

    private boolean validateResponse (String identityProvider, String serviceProvider, Response response, SamlValidationResults result2) 
    		throws InternalErrorException, AssertionValidationException, CertificateException, UnmarshallingException, SAXException, IOException, ParserConfigurationException
    {
    	SAML20ResponseValidator validator = getResponseValidator(identityProvider);
    	
    	if (response.isSigned())
    	{
	    	org.opensaml.saml.common.assertion.ValidationContext ctx = new ValidationContext();
	    	
			ValidationResult result = validator.validate(response, ctx);
			if (result != ValidationResult.VALID)
			{
				log.info("Error validating SAML message: "+ctx.getValidationFailureMessage());
				result2.setFailureReason(ctx.getValidationFailureMessage());
			}
    	}
		
		if ( ! validDate (response.getIssueInstant(), result2))
		{
			return false;
		}
		
		if ( response.getStatus() == null || response.getStatus().getStatusCode() == null)
		{
			result2.setFailureReason("Response does not contain status");
			log.info(result2.getFailureReason());
			return false;
		}
		
		if ( ! response.getStatus().getStatusCode().getValue().equals(StatusCode.SUCCESS))
		{
			result2.setFailureReason("Authentication failed Status "+response.getStatus().getStatusCode().getValue());
			log.info(result2.getFailureReason());
			return false;
		}

    	return true ;
    	
    }

    private SAML20ResponseValidator getResponseValidator(String identityProvider) throws InternalErrorException, CertificateException, UnmarshallingException, SAXException, IOException, ParserConfigurationException {
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
}
