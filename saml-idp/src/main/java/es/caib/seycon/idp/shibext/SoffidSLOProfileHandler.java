package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.CryptoOperationRequirementLevel;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AbstractSAML2ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.LogoutRequestConfiguration;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.BaseSAML2ProfileRequestContext;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.SLOProfileHandler;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.SLOProfileHandler.SLORequestContext;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.ng.exception.InternalErrorException;

public class SoffidSLOProfileHandler extends SLOProfileHandler {
	IdentifierGenerator generator;
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SoffidSLOProfileHandler.class);
    /** Canned SOAP fault. */
    private final String soapFaultResponseMessage =
"<env:Envelope xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
" <env:Body>" +
" <env:Fault>" +
" <faultcode>env:Client</faultcode>" +
" <faultstring>An error occurred processing the request.</faultstring>" +
" <detail/>" +
" </env:Fault>" +
" </env:Body>" +
"</env:Envelope>";

    public SoffidSLOProfileHandler(String newPath) throws NoSuchAlgorithmException {
		super(newPath);
		generator = new SecureRandomIdentifierGenerator();
	}

	/**
     * Process and respond to a SAML LogoutRequest message. This is a very simplified version
     * because it doesn't propagate the logout to any SPs. It just handles the IdP session(s)
     * and then either responds to the client or to the SP depending on the async flag.
     * 
     * @param inTransport   incoming transport object
     * @param outTransport  outgoing transport object
     * @throws ProfileException if an error occurs during profile execution
     */
    protected void processLogoutRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        LogoutResponse samlResponse = null;
        SLORequestContext requestContext = new SLORequestContext();

        try {
            decodeRequest(requestContext, inTransport, outTransport);

            ProfileConfiguration sloConfig =
                    requestContext.getRelyingPartyConfiguration().getProfileConfiguration(getProfileId());
            if (sloConfig == null) {
                requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null,
                        "SAML 2 SLO profile not configured"));
                String msg = "SAML 2 SLO profile is not configured for relying party "
                        + requestContext.getInboundMessageIssuer();
                log.warn(msg);
                throw new ProfileException(msg);
            }

            checkSamlVersion(requestContext);
            
            // Get session corresponding to NameID. This is limited to one session, which means
            // we can't know if more than one might have been issued for a particular NameID.
            SessionManager<Session> sessionManager = getSessionManager();
            String nameIDIndex = getSessionIndexFromNameID(requestContext.getSubjectNameIdentifier());
            log.debug("Querying SessionManager based on NameID '{}'", nameIDIndex);
            Session indexedSession = sessionManager.getSession(nameIDIndex);
            
            Status status = null;
            
            if (indexedSession == null) {
                // No session matched.
                log.info("LogoutRequest did not reference an active session.");
                status = buildStatus(StatusCode.SUCCESS_URI, null, null);
//                status = buildStatus(StatusCode.REQUESTER_URI, StatusCode.UNKNOWN_PRINCIPAL_URI, null);
            } else if (!indexedSession.getServicesInformation().keySet().contains(
                    requestContext.getInboundMessageIssuer())) {
                // Session matched, but it's not associated with the requesting SP.
                indexedSession = null;
                log.warn("Requesting entity is not a participant in the referenced session.");
                // status = buildStatus(StatusCode.REQUESTER_URI, StatusCode.UNKNOWN_PRINCIPAL_URI, null);
                status = buildStatus(StatusCode.SUCCESS_URI, null, null);
            } else if (getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
                // For SOAP, there's no active session and all we're doing is destroying the matched one.
                // If there are other service records attached, then it's a partial logout.
                if (indexedSession.getServicesInformation().keySet().size() > 1) {
                    status = requestLogout(requestContext, indexedSession);
                } else {
                	try {
						new Autenticator().notifyLogout (indexedSession);
					} catch (Exception e) {
						log.warn("Error closing soffid session", e);
					}
                    status = buildStatus(StatusCode.SUCCESS_URI, null, null);
                }
            } else {
                // Get active session and compare it to the matched one.
                Session activeSession = getUserSession(inTransport);
                if (activeSession == null ||
                        DatatypeHelper.safeEquals(activeSession.getSessionID(), indexedSession.getSessionID())) {
                    // If there are other service records attached, then it's a partial logout.
                    if (indexedSession.getServicesInformation().keySet().size() > 1) {
                        status = requestLogout(requestContext, indexedSession);
                    } else {
                    	try {
    						new Autenticator().notifyLogout (indexedSession);
    					} catch (Exception e) {
    						log.warn("Error closing soffid session", e);
    					}
                        status = buildStatus(StatusCode.SUCCESS_URI, null, null);
                    }
                } else {
                	try {
						new Autenticator().notifyLogout (indexedSession);
					} catch (Exception e) {
						log.warn("Error closing soffid session", e);
					}
                    // Session found, but it's not the same as the active session.
                    indexedSession = null;
                    log.warn("LogoutRequest referenced a session other than the client's current one.");
//                    status = buildStatus(StatusCode.REQUESTER_URI, StatusCode.UNKNOWN_PRINCIPAL_URI, null);
                    status = buildStatus(StatusCode.SUCCESS_URI, null, null);
                }
            }
            
            // Async means that we're not responding to the SP, but to the user.
            // SOAP is an outlying case, not technically expected, but we can just
            // return an empty response in that case.
            if (requestContext.isAsynchronous() && indexedSession != null) {
                if (getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
                    if (indexedSession != null) {
                        log.info("Invalidating session identified by LogoutRequest: {}", indexedSession.getSessionID());
                        status = requestLogout(requestContext, indexedSession);
                        destroySession(indexedSession);
                    }
                    try {
                        outTransport.setCharacterEncoding("UTF-8");
                        outTransport.setHeader("Content-Type", "text/plain");
                        outTransport.setStatusCode(HttpServletResponse.SC_OK);
                        Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
                        out.flush();
                     } catch (Exception we) {
                        log.error("Error returning empty response.", we);
                     }
                } else {
                    localLogout(indexedSession, inTransport, outTransport);
                }
                writeAuditLogEntry(requestContext);
                return;
            }
            
            if (status.getStatusCode().getValue().equals(StatusCode.SUCCESS_URI)) {
            	if (indexedSession != null)
            	{
	                log.info("Invalidating session identified by LogoutRequest: {}", indexedSession.getSessionID());
	                destroySession(indexedSession);
            	}
                samlResponse = buildLogoutResponse(requestContext, status);
            } else {
                requestContext.setFailureStatus(status);
                samlResponse = buildLogoutResponse(requestContext, null);
            }

        } catch (ProfileException e) {
            if (requestContext.getPeerEntityEndpoint() != null) {
                // This means it wasn't an Async LogoutRequest.
                if (requestContext.getFailureStatus() == null) {
                    requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, e.getMessage()));
                }
                samlResponse = buildLogoutResponse(requestContext, null);
            } else if (!requestContext.isAsynchronous()
                    && getInboundBinding().equals(SAMLConstants.SAML2_SOAP11_BINDING_URI)) {
                log.debug("Returning SOAP fault", e);
                try {
                   outTransport.setCharacterEncoding("UTF-8");
                   outTransport.setHeader("Content-Type", "application/soap+xml");
                   outTransport.setStatusCode(500);  // seem to lose the message when we report an error.
                   Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
                   out.write(soapFaultResponseMessage);
                   out.flush();
                } catch (Exception we) {
                   log.error("Error returning SOAP fault", we);
                }
                return;
            } else {
                throw e;
            }
        }

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());
        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }
       

    private Status requestLogout (SLORequestContext requestContext, Session indexedSession) throws ProfileException
    {
    	String status = StatusCode.SUCCESS_URI;
    	boolean allOk = true;
    	try {
			for (ServiceInformation si: indexedSession.getServicesInformation().values())
			{
				if (! si.getEntityID().equals(requestContext.getPeerEntityId()))
				{
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
				}
			}
		} catch (Exception e) {
			throw new ProfileException(e);
		}
    	return buildStatus(StatusCode.SUCCESS_URI, status, null);
    	
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


    /** Represents the internal state of a Logout Request while it's being processed by the IdP. */
    public class RemoteSLORequestContext
            extends BaseSAMLProfileRequestContext<LogoutResponse, LogoutRequest, NameID, LogoutRequestConfiguration> {
        
        /** Request included the aslo:Asynchronous extension. */
        private boolean async;
        
        /**
         * Indicates whether the request included the aslo:Asynchronous extension.
         * 
         * @return the async flag
         */
        public boolean isAsynchronous() {
            return async;
        }
        
        /**
         * Sets whether the request included the aslo:Asynchronous extension.
         * 
         * @param flag the async flag
         */
        public void setAsynchronous(boolean flag) {
            async = flag;
        }
    }

}
