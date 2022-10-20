package es.caib.seycon.idp.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;

import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
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
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.FederationMemberSession;
import com.soffid.iam.addons.federation.common.OauthToken;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.Session;

import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.TokenHandler;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.util.Base64;

public class LogoutHandler {
	private FederationService federationService;
	Log log = LogFactory.getLog(getClass());
	static BasicParserPool parserPool = new BasicParserPool();
	
	public LogoutResponse logout (ServletContext ctx, HttpServletRequest req, Session s, boolean userInitiated) throws InternalErrorException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, java.security.SignatureException {
		LogoutResponse l = new LogoutResponse();
		l.setFailedLogouts(new LinkedList<>());
		l.setFrontRequests(new LinkedList<>());
		
		federationService = new RemoteServiceLocator().getFederacioService();
		
		final List<FederationMemberSession> federationMemberSessions = federationService.findFederationMemberSessions(s.getId());
		for ( FederationMemberSession fms: federationMemberSessions) {
			FederationMember fm = federationService.findFederationMemberByPublicId(fms.getFederationMember());
			if (fm.getServiceProviderType() == ServiceProviderType.OPENID_CONNECT)
				processOpenidLogout(fms, ctx, s, l, userInitiated);
			if (fm.getServiceProviderType() == ServiceProviderType.CAS)
				processCasLogout(fms, ctx, s, l, userInitiated);
			if (fm.getServiceProviderType() == ServiceProviderType.SAML || fm.getServiceProviderType() == ServiceProviderType.SOFFID_SAML)
				processSamlLogout(fms, ctx, s, l, userInitiated);
		}
		
		for (OauthToken token: federationService.findOauthTokenBySessionId(s.getId())) {
			federationService.deleteOauthToken(token);
			final TokenHandler tokenHandler = TokenHandler.instance();
			TokenInfo t = tokenHandler.getToken(token.getFullToken());
			if (t != null)
				t.setExpires(System.currentTimeMillis());
		}
		
		if (! userInitiated || l.getFrontRequests().isEmpty()) {
			if (req != null) {
				FederationMember ip = IdpConfig.getConfig().getFederationMember();
		    	for (Cookie c: req.getCookies())
		    	{
		    		if (c.getName().equals(ip.getSsoCookieName()))
		    		{
		    			new RemoteServiceLocator()
		    				.getFederacioService()
		    				.expireSessionCookie(c.getValue());
		    		}
		    	}
			}
			try {
				for ( FederationMemberSession fms: federationMemberSessions) {
	    			new RemoteServiceLocator()
	    				.getFederacioService()
	    				.deleteFederatioMemberSession(fms);
				}
				new RemoteServiceLocator().getSessionService().destroySession(s);
			} catch (InternalErrorException e) {
				// Ignore already closed session
			}
		}

		return l;
	}

	private void processOpenidLogout(FederationMemberSession fms, ServletContext ctx, Session s, LogoutResponse l,
			boolean userInitiated) throws InternalErrorException, IOException {
		FederationMember sp;
		try {
			sp = new RemoteServiceLocator().getFederacioService().findFederationMemberByPublicId(fms.getFederationMember());
			IdpConfig c = IdpConfig.getConfig();
			final TokenHandler tokenHandler = TokenHandler.instance();
			String token = tokenHandler.generateLogoutToken(c, fms.getUserName(), fms.getSessionHash(), sp);
			if (sp.getOpenidLogoutUrlBack() != null && ! sp.getOpenidLogoutUrlBack().isEmpty())
			{
				String url = sp.getOpenidLogoutUrlBack();
				if (url != null && !url.isEmpty()) {
					try {
						HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
						conn.setRequestMethod("POST");
						conn.setDoOutput(true);
						conn.setDoInput(true);
						conn.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
						OutputStream os = conn.getOutputStream();
						String msg = "logout_token="+ URLEncoder.encode(token, "UTF-8") + "\n";
						os.write(msg.getBytes("UTF-8"));
						os.close();
						
						InputStream is = conn.getInputStream();
						while (is.read() >= 0) ;
						is.close();
						federationService.deleteFederatioMemberSession(fms);
						return;
					} catch (Exception e) {
						log.warn("Error closing session from "+ fms.getFederationMember(), e);
					}
				}
			}
			if (userInitiated && sp.getOpenidLogoutUrlFront() != null && !sp.getOpenidLogoutUrlFront().isEmpty()) {
				String url = sp.getOpenidLogoutUrlFront();
				if (! url.contains("?"))
					url = url + "?";
				if (! url.endsWith("?") && ! url.endsWith("&"))
					url = url + "&";
				
				url = url + "iss=" + URLEncoder.encode(tokenHandler.getIssuer(c, false), "UTF-8");
				url = url + "&sid="+ URLEncoder.encode(fms.getSessionHash(), "UTF-8");
				final FrontLogoutRequest frontLogoutRequest = new FrontLogoutRequest();
				frontLogoutRequest.setDescription(sp.getName());
				frontLogoutRequest.setPublicId(sp.getPublicId());
				frontLogoutRequest.setUrl(new URI(url));
				l.getFrontRequests().add(frontLogoutRequest);
				return;
			}
		} catch (Exception e) {
			log.warn("Error closing session from "+ fms.getFederationMember(), e);
		}
		l.getFailedLogouts().add(fms.getFederationMember());
	}

	private void processCasLogout(FederationMemberSession fms, ServletContext ctx, Session s, LogoutResponse l,
			boolean userInitiated) throws InternalErrorException, IOException {
		FederationMember sp;
		try {
			sp = new RemoteServiceLocator().getFederacioService().findFederationMemberByPublicId(fms.getFederationMember());
			IdpConfig c = IdpConfig.getConfig();
			final TokenHandler tokenHandler = TokenHandler.instance();
			for (OauthToken token: federationService.findOauthTokenBySessionId(s.getId())) {
				if (fms.getFederationMember().equals( token.getServiceProvider() ) &&
					fms.getSessionHash().equals(token.getOauthSession())) {
					TokenInfo t = tokenHandler.getToken(token.getTokenId());
					if (t != null) {
						if (sp.getOpenidLogoutUrlBack() != null && ! sp.getOpenidLogoutUrlBack().isEmpty())
						{
							String url = sp.getOpenidLogoutUrlBack();
							if (url != null && !url.isEmpty()) {
								try {
									String msg = generateMessage(t);
									HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
									conn.setRequestMethod("POST");
									conn.setDoOutput(true);
									conn.setDoInput(true);
									conn.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
									OutputStream os = conn.getOutputStream();
									os.write(msg.getBytes("UTF-8"));
									os.close();
									
									InputStream is = conn.getInputStream();
									while (is.read() >= 0) ;
									is.close();
									federationService.deleteFederatioMemberSession(fms);
									return;
								} catch (Exception e) {
									log.warn("Error closing session from "+ fms.getFederationMember(), e);
								}
							}
						}
						if (userInitiated && sp.getOpenidLogoutUrlFront() != null && !sp.getOpenidLogoutUrlFront().isEmpty()) {
							String msg = generateMessage(t);
							StringBuffer sb = new StringBuffer(sp.getOpenidLogoutUrlFront());
							if (sb.indexOf("?") >= 0)
								sb.append("&");
							else
								sb.append("?");
							sb.append("callback=console.log&request=")
								.append(Base64.encodeBytes(msg.getBytes(StandardCharsets.UTF_8)))
								.append("&_=")
								.append(System.currentTimeMillis());
							FrontLogoutRequest req = new FrontLogoutRequest();
							req.setDescription(sp.getName());
							req.setPublicId(sp.getPublicId());
							req.setUrl(new URI(sb.toString()));
							l.getFrontRequests().add(req);
							return;
						}
					}
				}
			}
		} catch (Exception e) {
			log.warn("Error closing session from "+ fms.getFederationMember(), e);
		}
		l.getFailedLogouts().add(fms.getFederationMember());
	}

	private String generateMessage(TokenInfo t) throws NoSuchAlgorithmException {
		SimpleDateFormat simpleDf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		simpleDf.setTimeZone(TimeZone.getTimeZone("GMT"));
		String msg = "<samlp:LogoutRequest\n"
				+ "    xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n"
				+ "    xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n"
				+ "    ID=\""+new SecureRandomIdentifierGenerator().generateIdentifier()+"\"\n"
				+ "    Version=\"2.0\"\n"
				+ "    IssueInstant=\""+simpleDf.format(new Date())+"\">\n"
				+ "    <saml:NameID>@NOT_USED@</saml:NameID>\n"
				+ "    <samlp:SessionIndex>"+t.getToken()+"</samlp:SessionIndex>\n"
				+ "</samlp:LogoutRequest>";
		return msg;
	}

	private void processSamlLogout(FederationMemberSession fms, ServletContext ctx, Session session, LogoutResponse l, boolean userInitiated) throws InternalErrorException, IOException {
		MetadataProvider metadataProvider;
        RelyingPartyConfigurationManager rpConfigMngr = HttpServletHelper.getRelyingPartyConfigurationManager(ctx);
		if (rpConfigMngr instanceof SAMLMDRelyingPartyConfigurationManager) {
            SAMLMDRelyingPartyConfigurationManager samlRpConfigMngr = (SAMLMDRelyingPartyConfigurationManager) rpConfigMngr;
            metadataProvider = samlRpConfigMngr.getMetadataProvider();
        }
		else
			throw new InternalErrorException("Cannot get metadata provider");

		String status = StatusCode.SUCCESS_URI;
    	boolean allOk = true;
    	try {
			EntityDescriptor remoteEntity = metadataProvider.getEntityDescriptor(fms.getFederationMember());
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
					
						status = sendSamlLogoutRequest(session, fms, slo, (SAMLMDRelyingPartyConfigurationManager) rpConfigMngr, userInitiated);
				        
					}
				}
			}
			federationService.deleteFederatioMemberSession(fms);
		} catch (Exception e) {
			FederationMember fm = new RemoteServiceLocator().getFederacioService().findFederationMemberByPublicId(fms.getFederationMember());
			if (fm == null)
				l.getFailedLogouts().add(fms.getFederationMember());
			else
				l.getFailedLogouts().add(fm.getName());
		}
    }

	private String sendSamlLogoutRequest(Session session, FederationMemberSession fms, 
			SingleLogoutService slo, SAMLMDRelyingPartyConfigurationManager rpConfigMngr, boolean userInitiated) 
		throws Exception {
		
		FederationMember idp = IdpConfig.getConfig().findIdentityProviderForRelyingParty(fms.getFederationMember());
		Issuer issuer = buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME, IssuerBuilder.class);
		issuer.setValue(idp.getPublicId());

		LogoutRequest request = buildSamlObject(LogoutRequest.DEFAULT_ELEMENT_NAME, LogoutRequestBuilder.class);
		request.setDestination(slo.getBinding());
		request.setIssueInstant(DateTime.now());
		request.setIssuer(issuer);
		NameID nameid = buildSamlObject(NameID.DEFAULT_ELEMENT_NAME, NameIDBuilder.class);
		nameid.setValue(fms.getUserName());
		nameid.setFormat(fms.getUserNameFormat());
		nameid.setNameQualifier(fms.getUserNameQualifier());
		request.setNameID(nameid);
		String reason;
		if (userInitiated)
			reason = LogoutRequest.USER_REASON;
		else
			reason = LogoutRequest.ADMIN_REASON;
		request.setReason(reason);
		request.setID( new SecureRandomIdentifierGenerator().generateIdentifier() );
		
      
		RelyingPartyConfiguration rpc = rpConfigMngr.getRelyingPartyConfiguration(idp.getPublicId());
		if (rpc == null)
			rpc = rpConfigMngr.getDefaultRelyingPartyConfiguration();
		
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
		HttpSOAPClient soapClient = new HttpSOAPClient(clientBuilder.buildClient(), parserPool);
		 
		String status = StatusCode.SUCCESS_URI;
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
		        log.warn("Unexpected SOAP body content.  Expected a SAML request but recieved "+ incommingMessage
		                .getElementQName());
		        throw new MessageDecodingException("Unexpected SOAP body content.  Expected a SAML request but received "
		                + incommingMessage.getElementQName());
		    }
		    SAMLObject samlMessage = (SAMLObject) incommingMessage;
		    org.opensaml.saml2.core.LogoutResponse response = (org.opensaml.saml2.core.LogoutResponse) samlMessage;
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
			log.warn("Error logging out from"+fms.getFederationMember(), e);
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
