package es.caib.seycon.idp.server;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKeyResolver;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.FederationMemberSession;
import com.soffid.iam.addons.federation.common.OauthToken;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.Session;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.LogoutRequestConfiguration;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.SLOProfileHandler.SLORequestContext;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import es.caib.seycon.idp.openid.server.TokenHandler;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.ng.exception.InternalErrorException;

public class LogoutHandler {
	private FederationService federationService;
	Log log = LogFactory.getLog(getClass());

	public LogoutResponse logout (Session s) throws InternalErrorException, IOException {
		LogoutResponse l = new LogoutResponse();
		l.setFailedLogouts(new LinkedList<>());
		l.setFrontRequests(new LinkedList<>());
		
		federationService = new RemoteServiceLocator().getFederacioService();
		for ( FederationMemberSession fms: federationService.findFederationMemberSessions(s.getId())) {
			FederationMember fm = federationService.findFederationMemberByPublicId(fms.getFederationMember());
			if (fm.getServiceProviderType() == ServiceProviderType.OPENID_CONNECT)
				processOpenidLogout(fms, l);
			if (fm.getServiceProviderType() == ServiceProviderType.SAML || fm.getServiceProviderType() == ServiceProviderType.SOFFID_SAML)
				processSamlLogout(fms, l);
		}
		
		for (OauthToken token: federationService.findOauthTokenBySessionId(s.getId())) {
			federationService.deleteOauthToken(token);
			final TokenHandler tokenHandler = TokenHandler.instance();
			TokenInfo t = tokenHandler.getToken(token.getFullToken());
			if (t != null)
				t.setExpires(System.currentTimeMillis());
		}
		
		new RemoteServiceLocator().getSessionService().destroySession(s);

		return l;
	}

	private void processSamlLogout(FederationMemberSession fms, LogoutResponse l) {
		// TODO Auto-generated method stub
		
	}

	private void processOpenidLogout(FederationMemberSession fms, LogoutResponse l) {
    	String status = StatusCode.SUCCESS_URI;
    	boolean allOk = true;
    	try {
			EntityDescriptor remoteEntity = getMetadataProvider().getEntityDescriptor(si.getEntityID());
			SPSSODescriptor descriptor = remoteEntity.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
			SAMLMessageEncoder encoder;
			if (descriptor == null)
				status = StatusCode.PARTIAL_LOGOUT_URI;
			else
			{
				for (SingleLogoutService slo: descriptor.getSingleLogoutServices())
				{
					if ( SAMLConstants.SAML2_SOAP11_BINDING_URI.equals ( slo.getBinding()) )
					{
					
						status = sendLogoutRequest(requestContext,
								indexedSession, status, si, slo);
				        
					}
				}
			}
		} catch (Exception e) {
			throw new ProfileException(e);
		}
    }

	protected String sendLogoutRequest(SLORequestContext requestContext,
			Session indexedSession, String status, ServiceInformation si,
			SingleLogoutService slo) throws SecurityException,
			MessageEncodingException, MarshallingException, SignatureException {
		Issuer issuer = buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME, IssuerBuilder.class);
		issuer.setValue(requestContext.getLocalEntityId());

		LogoutRequest request = buildSamlObject(LogoutRequest.DEFAULT_ELEMENT_NAME, LogoutRequestBuilder.class);
		request.setDestination(slo.getBinding());
		request.setIssueInstant(DateTime.now());
		request.setIssuer(issuer);
		NameID nameid = buildSamlObject(NameID.DEFAULT_ELEMENT_NAME, NameIDBuilder.class);
		nameid.setValue(si.getNameIdentifier());
		nameid.setFormat(si.getNameIdentifierFormat());
		nameid.setNameQualifier(si.getNameQualifier());
		request.setNameID(nameid);
		String reason = requestContext.getInboundSAMLMessage().getReason();
		if (reason == null)
			reason = LogoutRequest.USER_REASON;
		request.setReason(reason);
//		SessionIndex sessionindex = buildSamlObject(SessionIndex.DEFAULT_ELEMENT_NAME, SessionIndexBuilder.class);
//		sessionindex.setSessionIndex(indexedSession.getSessionID());
//		request.getSessionIndexes().add(sessionindex);
		request.setID( generator.generateIdentifier() );
		
      
		RelyingPartyConfiguration rpc = getRelyingPartyConfiguration(si.getEntityID());
		Credential signingCredential = rpc.getDefaultSigningCredential();
		
		if (signingCredential != null)
		{
			Signature signature =  (Signature) Configuration.getBuilderFactory()
		            .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
		            .buildObject(Signature.DEFAULT_ELEMENT_NAME);
			
		    request.setSignature(signature);
			signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			
		    SecurityHelper.prepareSignatureParams(signature, signingCredential, null, null);
		    
		    Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
		    if (marshaller == null) {
		        throw new MessageEncodingException("No marshaller registered for "
		                + request.getElementQName() + ", unable to marshall in preperation for signing");
		    }
		    marshaller.marshall(request);
		    
		    Signer.signObject(signature);
		}


		
		Envelope envelope = buildSOAP11Envelope(request);
		
		// SOAP context used by the SOAP client
		BasicSOAPMessageContext soapContext = new BasicSOAPMessageContext();
		soapContext.setOutboundMessage(envelope);
		// Build the SOAP client
		HttpClientBuilder clientBuilder = new HttpClientBuilder();
		clientBuilder.setHttpsProtocolSocketFactory(new TLSProtocolSocketFactory(null, buildNoTrustTrustManager()));
		 
//		HttpSOAPClient soapClient = new DebugHttpSoapClient(clientBuilder.buildClient(), getParserPool());
		HttpSOAPClient soapClient = new HttpSOAPClient(clientBuilder.buildClient(), getParserPool());
		 
		// Send the message
		try {
		    soapClient.send(slo.getLocation(), soapContext);
		    
		    // Access the SOAP response envelope
		    Envelope soapResponse = (Envelope) soapContext.getInboundMessage();
		     
		    List<XMLObject> soapBodyChildren = soapResponse.getBody().getUnknownXMLObjects();
		    if (soapBodyChildren.size() < 1 || soapBodyChildren.size() > 1) {
		        log.error("Unexpected number of children in the SOAP body, " + soapBodyChildren.size()
		                + ".  Unable to extract SAML message");
		        throw new MessageDecodingException(
		                "Unexpected number of children in the SOAP body, unable to extract SAML message");
		    }

		    XMLObject incommingMessage = soapBodyChildren.get(0);
		    if (!(incommingMessage instanceof SAMLObject)) {
		        log.error("Unexpected SOAP body content.  Expected a SAML request but recieved {}", incommingMessage
		                .getElementQName());
		        throw new MessageDecodingException("Unexpected SOAP body content.  Expected a SAML request but recieved "
		                + incommingMessage.getElementQName());
		    }
		    SAMLObject samlMessage = (SAMLObject) incommingMessage;
		    LogoutResponse response = (LogoutResponse) samlMessage;
		    Status responseStatus = response.getStatus();
		    if (responseStatus != null && !responseStatus.isNil() 
		    		&& !responseStatus.getStatusCode().getValue().equals( StatusCode.SUCCESS_URI))
		    {
		    	if ( StatusCode.RESPONDER_URI.equals(responseStatus.getStatusCode().getValue()) &&
		    			responseStatus.getStatusCode().getStatusCode() != null &&
		    			StatusCode.PARTIAL_LOGOUT_URI.equals(responseStatus.getStatusCode().getStatusCode().getValue()))
		    	{
			    	log.info(String.format("Notified partial logout from %s"
			    			,slo.getLocation()));
		    	}
		    	else
		    	{
			    	log.warn(String.format("Error notifying logout to %s. Status=[%s]"
			    			,slo.getLocation(), responseStatus == null ? "NULL RESPONSE STATUS":
			    				(responseStatus.getStatusCode() == null ? "NULL STATUS CODE":
			    					responseStatus.getStatusCode().getValue()) + " - " + responseStatus.getStatusMessage()));
			    	status = StatusCode.PARTIAL_LOGOUT_URI;
		    	}
		    }
		    else
		    {
		    	log.info(String.format("Notified logout from %s"
		    			,slo.getLocation()));
		    }
		} catch (Exception e) {
			log.info("Error logging out from {}", si.getEntityID());
			log.warn("Exception throwwn: ", e);
		}
		return status;
	}

    
    private <SAMLObjectType extends SAMLObject, BuilderT extends SAMLObjectBuilder<SAMLObjectType>> SAMLObjectType 
    	buildSamlObject(javax.xml.namespace.QName defaultElementName, Class<BuilderT> type) {
    	
        XMLObjectBuilderFactory builderFactory = org.opensaml.Configuration.getBuilderFactory();
        BuilderT requestBuilder = (BuilderT)builderFactory.getBuilder(defaultElementName);
        return requestBuilder.buildObject();
    }
    
    
    private static Envelope buildSOAP11Envelope(XMLObject payload) {
        XMLObjectBuilderFactory bf = Configuration.getBuilderFactory();
        Envelope envelope = (Envelope) bf.getBuilder(Envelope.DEFAULT_ELEMENT_NAME).buildObject(Envelope.DEFAULT_ELEMENT_NAME);
        Body body = (Body) bf.getBuilder(Body.DEFAULT_ELEMENT_NAME).buildObject(Body.DEFAULT_ELEMENT_NAME);
         
        body.getUnknownXMLObjects().add(payload);
        envelope.setBody(body);
         
        return envelope;
    }

    /**
     * Builds a {@link X509TrustManager} which bypasses all X.509 validation steps.
     * 
     * @return the trustless trust manager
     */
    protected X509TrustManager buildNoTrustTrustManager() {
        X509TrustManager noTrustManager = new X509TrustManager() {

            /** {@inheritDoc} */
            public void checkClientTrusted(X509Certificate[] certs, String auth) {
            }

            /** {@inheritDoc} */
            public void checkServerTrusted(X509Certificate[] certs, String auth) {
            }

            /** {@inheritDoc} */
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[] {};
            }
        };

        return noTrustManager;
    }



}
