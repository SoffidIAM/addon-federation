package es.caib.seycon.idp.shibext;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

import javax.crypto.SecretKey;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
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
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKeyResolver;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
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
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.soffid.iam.addons.federation.common.FederationMemberSession;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AbstractSAML2ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.LogoutRequestConfiguration;
import edu.internet2.middleware.shibboleth.common.session.SessionManager;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.BaseSAML2ProfileRequestContext;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.SLOProfileHandler;
import edu.internet2.middleware.shibboleth.idp.session.ServiceInformation;
import edu.internet2.middleware.shibboleth.idp.session.Session;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.LogoutHandler;
import es.caib.seycon.idp.ui.LogoutServlet;
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

    private static String[] candidateNameIdFormat = new String [] {
			NameID.PERSISTENT, NameID.TRANSIENT,NameID.UNSPECIFIED,NameID.EMAIL
    };
    
	/**
     * Process and respond to a SAML LogoutRequest message. This is a very simplified version
     * because it doesn't propagate the logout to any SPs. It just handles the IdP session(s)
     * and then either responds to the client or to the SP depending on the asynnullc flag.
     * 
     * @param inTransport   incoming transport object
     * @param outTransport  outgoing transport object
     * @throws ProfileException if an error occurs during profile execution
     */
    
    protected void processLogoutRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport)
            throws ProfileException {

        LogoutResponse samlResponse = null;
        SLORequestContext requestContext = new SLORequestContext();
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
        HttpServletResponse httpResponse = ((HttpServletResponseAdapter) outTransport).getWrappedResponse();
        ServletContext servletContext = httpRequest.getSession().getServletContext();

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
            SessionManager<Session> sessionManager = getSessionManager();
            NameID nameId = requestContext.getSubjectNameIdentifier();

            Status status = buildStatus(StatusCode.SUCCESS_URI, null, null);
            com.soffid.iam.api.Session soffidSession = new Autenticator().getSession(httpRequest, false);
            if (soffidSession != null) {
            	es.caib.seycon.idp.server.LogoutResponse logout = new LogoutHandler().logout(servletContext, httpRequest, soffidSession, true);
            	if (!logout.getFrontRequests().isEmpty())
            	{
            		httpResponse.sendRedirect(LogoutServlet.URI);
            		return;
            	}
            } else {
            	FederationService fs = IdpConfig.getConfig().getFederationService();
            	for (FederationMemberSession fms: fs.findFederationMemberSessions(requestContext.getPeerEntityId(), nameId.getValue())) {
            		com.soffid.iam.api.Session v = new com.soffid.iam.api.Session();
            		v.setId(fms.getId());
            		v.setStartDate(Calendar.getInstance());
            		v.setUserName(nameId.getValue());
            		try {
            			new LogoutHandler().logout(servletContext, httpRequest, v, false);
            		} catch (Exception e) {
            			log.warn("Error closing session", e);
            		}
            	}
            }
            
            samlResponse = buildLogoutResponse(requestContext, status);

            if (requestContext.isAsynchronous()) {
        		httpResponse.sendRedirect(LogoutServlet.URI);
        		return;
            }
        } catch (ProfileException e) {
            NameID nameId = requestContext.getSubjectNameIdentifier();
            if (!requestContext.isAsynchronous()
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
            } else if (isGlobalSessionActive(httpRequest) && isOldSession(requestContext, nameId, httpRequest)){
            	try {
            		log.info("Error performing logout. Doing manual logout ", e);
					httpResponse.sendRedirect("/logout.jsp");
					return;
				} catch (IOException e1) {
					if (requestContext.getFailureStatus() == null) {
						requestContext.setFailureStatus(buildStatus(StatusCode.RESPONDER_URI, null, e.getMessage()));
					}
					samlResponse = buildLogoutResponse(requestContext, null);
				}
            } else {
            	requestContext.setFailureStatus(buildStatus(StatusCode.SUCCESS_URI, null, null));
				samlResponse = buildLogoutResponse(requestContext, null);
				deleteOldSession(requestContext, nameId, httpRequest);
			}
        } catch (Exception e) {
			throw new ProfileException("Error performing logout", e);
		}

        requestContext.setOutboundSAMLMessage(samlResponse);
        requestContext.setOutboundSAMLMessageId(samlResponse.getID());
        requestContext.setOutboundSAMLMessageIssueInstant(samlResponse.getIssueInstant());
        encodeResponse(requestContext);
        writeAuditLogEntry(requestContext);
    }

    private boolean isGlobalSessionActive(HttpServletRequest httpRequest) {
    	try {
			return new Autenticator().getSession(httpRequest, false) != null;
		} catch (Exception e) {
			return false;
		}
    }

    private boolean isOldSession(BasicSAMLMessageContext<LogoutRequest, LogoutResponse, NameID> requestContext, 
    		NameIDType nameId, HttpServletRequest httpRequest) {
    	try {
			FederationService fs = IdpConfig.getConfig().getFederationService();
			for (FederationMemberSession fms: fs.findFederationMemberSessions(
					requestContext.getPeerEntityId(), nameId.getValue())) {
				return true;
			}
		} catch (Exception e) {
			return false;
		}
    	return false;
	}

    private void deleteOldSession(BasicSAMLMessageContext<LogoutRequest, LogoutResponse, NameID> requestContext, 
    		NameIDType nameId, HttpServletRequest httpRequest) {
    	try {
			FederationService fs = IdpConfig.getConfig().getFederationService();
			for (FederationMemberSession fms: fs.findFederationMemberSessions(
					requestContext.getPeerEntityId(), nameId.getValue())) {
				fs.deleteFederatioMemberSession(fms);
			}
		} catch (Exception e) {
		}
	}


	/** {@inheritDoc} */
    @Override
    protected void populateSAMLMessageInformation(BaseSAMLProfileRequestContext requestContext)
            throws ProfileException {
        if (requestContext.getInboundSAMLMessage() instanceof LogoutRequest) {
            LogoutRequest request = (LogoutRequest) requestContext.getInboundSAMLMessage();
            requestContext.setPeerEntityId(request.getIssuer().getValue());
            requestContext.setInboundSAMLMessageId(request.getID());
            if (request.getNameID() != null) {
                requestContext.setSubjectNameIdentifier(request.getNameID());
            } else if (request.getEncryptedID() != null) {
                try {
					requestContext.setSubjectNameIdentifier(decrypt(requestContext, request.getEncryptedID()));
				} catch (Exception e) {
					throw new ProfileException("Unable to decrypt EncryptedID.", e);
				}
            } else {
                throw new ProfileException("Incoming LogoutRequest did not contain SAML2 NameID.");
            }
        }
    }
    
	private SAMLObject decrypt(BaseSAMLProfileRequestContext requestContext, EncryptedID encryptedID) throws Exception {		
        Decrypter decrypter = getDecrypter(requestContext);
        SAMLObject result = decrypter.decrypt(encryptedID);
        if (! (result instanceof NameID)) {
            throw new DecryptionException("Decrypted SAMLObject was not an instance of NameID");
        }
        return (NameID) result;
	}

    protected Decrypter getDecrypter(BaseSAMLProfileRequestContext requestContext) throws SecurityException {
        SecurityConfiguration securityConfiguration = Configuration.getGlobalSecurityConfiguration();

        Credential credential = requestContext.getRelyingPartyConfiguration().getDefaultSigningCredential();

		KeyInfoCredentialResolver credentialResolver = new StaticKeyInfoCredentialResolver(credential);
		EncryptedKeyResolver encryptedKeyResolver = new InlineEncryptedKeyResolver();
		//        dataDecParams.setBlacklistedAlgorithms(keyEncParams.getb);
		Decrypter decrypter = new Decrypter(credentialResolver, credentialResolver, encryptedKeyResolver );
        return decrypter;
    }

}
