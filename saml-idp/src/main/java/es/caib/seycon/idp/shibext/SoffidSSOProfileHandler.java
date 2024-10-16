package es.caib.seycon.idp.shibext;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.util.DatatypeHelper;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.FederationMemberSession;

import edu.internet2.middleware.shibboleth.common.attribute.AttributeRequestException;
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.encoding.AttributeEncodingException;
import edu.internet2.middleware.shibboleth.common.attribute.provider.SAML2AttributeAuthority;
import edu.internet2.middleware.shibboleth.common.profile.ProfileException;
import edu.internet2.middleware.shibboleth.common.profile.provider.BaseSAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.AbstractSAML2ProfileConfiguration;
import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.Saml2LoginContext;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.AbstractSAML2ProfileHandler;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.BaseSAML2ProfileRequestContext;
import edu.internet2.middleware.shibboleth.idp.profile.saml2.SSOProfileHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.session.LoginTimeoutHandler;
import es.caib.seycon.ng.exception.InternalErrorException;

public class SoffidSSOProfileHandler extends SSOProfileHandler {
	Log log = LogFactory.getLog(getClass());
	
	public SoffidSSOProfileHandler(String authnManagerPath) {
		super(authnManagerPath);
	}
	
	ThreadLocal<FederationMemberSession> pendingSession =  new ThreadLocal<>();

    /** {@inheritDoc} */
    public void processRequest(HTTPInTransport inTransport, HTTPOutTransport outTransport) throws ProfileException {
        HttpServletRequest httpRequest = ((HttpServletRequestAdapter) inTransport).getWrappedRequest();
		FederationMemberSession fms = (FederationMemberSession) httpRequest.getSession().getAttribute("$$soffid_incomplete_fms$$");
		pendingSession.set(fms);
		super.processRequest(inTransport, outTransport);
		if (httpRequest.getParameter("SAMLRequest") != null) {
			try {
				HttpServletResponse httpResponse = ((HttpServletResponseAdapter) outTransport).getWrappedResponse();
				ServletContext servletContext = httpRequest.getSession().getServletContext();
				
				LoginContext loginContext = HttpServletHelper.getLoginContext(getStorageService(),
						servletContext, httpRequest);
				
				if(loginContext != null){
					AuthenticationContext ctx = AuthenticationContext.fromRequest(httpRequest);
					if (ctx == null) {
						ctx = new AuthenticationContext();
	        			ctx.setPublicId(loginContext.getRelyingPartyId());
	        			ctx.initialize(httpRequest);
	        			ctx.store(httpRequest);
					}
					else {
						ctx.updateAllowedAuthenticationMethods();
					}
					if (ctx.isAlwaysAskForCredentials() || loginContext.isForceAuthRequired()) {
						loginContext.setPrincipalAuthenticated(true);
						Cookie[] requestCookies = httpRequest.getCookies();
						if (requestCookies != null) {
							for (Cookie requestCookie : requestCookies) {
								if (requestCookie != null && DatatypeHelper.safeEquals(requestCookie.getName(), HttpServletHelper.LOGIN_CTX_KEY_NAME)) {
									requestCookie.setValue(null);
								}
							}
						}
					}
					if (fms != null)
						fms.setSessionHash(loginContext.getSessionID());
				}
			} catch (Exception e) {
				throw new ProfileException("Error processing request", e);
			}
		}
		pendingSession.remove();
    }

    protected void resolveAttributes(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
        AbstractSAML2ProfileConfiguration profileConfiguration = requestContext.getProfileConfiguration();
        SAML2AttributeAuthority attributeAuthority = profileConfiguration.getAttributeAuthority();
        try {
            Map<String, BaseAttribute> principalAttributes = attributeAuthority.getAttributes(requestContext);

            requestContext.setAttributes(principalAttributes);
        } catch (SecurityException e) {
        	requestContext.setFailureStatus( buildStatus(
        			StatusCode.RESPONDER_URI, 
        			"urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
        			"Not authorized") );
        	throw new ProfileException("Not authorized", e);
        } catch (AttributeRequestException e) {
            log.warn(
                    "Error resolving attributes for principal '"+
                    		requestContext.getPrincipalName()
            				+"'. No name identifier or attribute statement will be included in response");
            
        }
    }
    
    protected NameID buildNameId(BaseSAML2ProfileRequestContext<?, ?, ?> requestContext) throws ProfileException {
    	String requiredNameIdFormat = getRequiredNameIDFormat(requestContext);
    	if (requiredNameIdFormat == null ||
    			requiredNameIdFormat.equals(NameID.TRANSIENT)) {
	    	NameID nameId = super.buildNameId(requestContext);
	    	FederationMemberSession fms = pendingSession.get();
	    	if (nameId != null && fms != null) {
	    		fms.setUserName(nameId.getValue());
	    		fms.setUserNameFormat(nameId.getFormat());
	    		fms.setUserNameQualifier(nameId.getNameQualifier());
	    		fms.setSessionHash(requestContext.getUserSession().getSessionID());
	    		try {
					IdpConfig.getConfig().getFederationService().createFederatioMemberSession(fms);
				} catch (UnrecoverableKeyException | InvalidKeyException | KeyStoreException | NoSuchAlgorithmException
						| CertificateException | IllegalStateException | NoSuchProviderException | SignatureException
						| InternalErrorException | IOException e) {
					throw new ProfileException("Error registering session", e);
				}
	    	}
	    	return nameId;
    	} else {
            SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) Configuration.getBuilderFactory().getBuilder(
                    NameID.DEFAULT_ELEMENT_NAME);
            NameID nameId = nameIdBuilder.buildObject();

            nameId.setValue(requestContext.getPrincipalName());
            nameId.setFormat(requiredNameIdFormat);

            return nameId;
    	}
    }

    /** {@inheritDoc} */
    protected String getRequiredNameIDFormat(BaseSAMLProfileRequestContext requestContext) {
    	String sp = requestContext.getPeerEntityId();
    	try {
			FederationMember fm = IdpConfig.getConfig().getFederationService().findFederationMemberByPublicId(sp);
			if (fm != null && fm.getNameIdFormat() != null) {
				if ("Persistent".equalsIgnoreCase(fm.getNameIdFormat()))
					return NameID.PERSISTENT;
				if ("Transient".equalsIgnoreCase(fm.getNameIdFormat()))
					return NameID.TRANSIENT;
				if ("Unspecified".equalsIgnoreCase(fm.getNameIdFormat()))
					return NameID.UNSPECIFIED;
				if ("Email".equalsIgnoreCase(fm.getNameIdFormat()))
					return NameID.EMAIL;
			}
		} catch (Exception e) {
			throw new RuntimeException("Error searching for service provider "+sp, e);
		}
        String requiredNameFormat = super.getRequiredNameIDFormat(requestContext);
        if (requiredNameFormat != null && ! isSupportedNameFormat(requiredNameFormat) ||
        		"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".equals(requiredNameFormat))
        	requiredNameFormat = null;

        return requiredNameFormat;
    }

	private boolean isSupportedNameFormat(String requiredNameFormat) {
		if (NameID.UNSPECIFIED.equals(requiredNameFormat))
			return true;
		if (NameID.TRANSIENT.equals(requiredNameFormat))
			return true;
		if (NameID.PERSISTENT.equals(requiredNameFormat))
			return true;
		if (NameID.EMAIL.equals(requiredNameFormat))
			return true;
		return false;
	}

}
