package es.caib.seycon.idp.openid.server;

import java.util.Collection;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.handler.HandlerChainResolver;
import org.opensaml.ws.security.SecurityPolicyResolver;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.credential.Credential;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.profile.provider.SAMLProfileRequestContext;
import edu.internet2.middleware.shibboleth.common.relyingparty.ProfileConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfiguration;
import edu.internet2.middleware.shibboleth.common.relyingparty.RelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.relyingparty.provider.SAMLMDRelyingPartyConfigurationManager;
import edu.internet2.middleware.shibboleth.common.session.Session;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import es.caib.seycon.idp.config.IdpConfig;

public class DummySamlRequestContext2 implements
		SAMLProfileRequestContext {

	private String user;
	String serviceProvider;
	String authenticationMethod;
	private ServletContext context;

	public DummySamlRequestContext2(ServletContext context, String user, String authenticationMethod, String serviceProvider) {
		this.user = user;
		this.authenticationMethod = authenticationMethod;
		this.serviceProvider = serviceProvider;
		this.context = context;
	}

	public SAMLObject getInboundSAMLMessage() {
		return null;
	}

	public String getInboundSAMLMessageId() {
		return null;
	}

	public DateTime getInboundSAMLMessageIssueInstant() {
		return new DateTime();
	}

	public String getInboundSAMLProtocol() {
		return "openid-connect";
	}

	public String getLocalEntityId() {
		try {
			return IdpConfig.getConfig().getFederationMember().getPublicId();
		} catch (Exception e) {
			return null;
		}
	}

	public EntityDescriptor getLocalEntityMetadata() {
		return HttpServletHelper.getRelyingPartyMetadata(getLocalEntityId(), 
				HttpServletHelper.getRelyingPartyConfigurationManager(context)
				);
	}

	public QName getLocalEntityRole() {
		return null;
	}

	public RoleDescriptor getLocalEntityRoleMetadata() {
		return null;
	}

	public MetadataProvider getMetadataProvider() {
        RelyingPartyConfigurationManager rpConfigMngr = HttpServletHelper.getRelyingPartyConfigurationManager(context);
		if (rpConfigMngr instanceof SAMLMDRelyingPartyConfigurationManager) {
            SAMLMDRelyingPartyConfigurationManager samlRpConfigMngr = (SAMLMDRelyingPartyConfigurationManager) rpConfigMngr;
            return samlRpConfigMngr.getMetadataProvider();
        }
		return null;
	}

	public Credential getOuboundSAMLMessageSigningCredential() {
		return null;
	}

	public byte[] getOutboundMessageArtifactType() {
		return null;
	}

	public SAMLObject getOutboundSAMLMessage() {
		return null;
	}

	public String getOutboundSAMLMessageId() {
		return null;
	}

	public DateTime getOutboundSAMLMessageIssueInstant() {
		return new DateTime();
	}

	public String getOutboundSAMLProtocol() {
		return "openid-connect";
	}

	public Endpoint getPeerEntityEndpoint() {
		return null;
	}

	public String getPeerEntityId() {
		return serviceProvider;
	}

	public EntityDescriptor getPeerEntityMetadata() {
		try {
			return getMetadataProvider().getEntityDescriptor(serviceProvider);
		} catch (MetadataProviderException e) {
			throw new RuntimeException("Error fetching metadata for "+serviceProvider, e);
		}
	}

	public QName getPeerEntityRole() {
		return null;
	}

	public RoleDescriptor getPeerEntityRoleMetadata() {
		return null;
	}

	public String getRelayState() {
		return null;
	}

	public SAMLObject getSubjectNameIdentifier() {
		return null;
	}

	public boolean isInboundSAMLMessageAuthenticated() {
		return false;
	}

	public void setInboundSAMLMessage(SAMLObject message) {
	}

	public void setInboundSAMLMessageAuthenticated(boolean isAuthenticated) {
	}

	public void setInboundSAMLMessageId(String id) {
	}

	public void setInboundSAMLMessageIssueInstant(DateTime instant) {
	}

	public void setInboundSAMLProtocol(String protocol) {
	}

	public void setLocalEntityId(String id) {
	}

	public void setLocalEntityMetadata(EntityDescriptor metadata) {
	}

	public void setLocalEntityRole(QName role) {
	}

	public void setLocalEntityRoleMetadata(RoleDescriptor role) {
	}

	public void setMetadataProvider(MetadataProvider provider) {
	}

	public void setOutboundMessageArtifactType(byte[] type) {
	}

	public void setOutboundSAMLMessage(SAMLObject message) {
	}

	public void setOutboundSAMLMessageId(String id) {
	}

	public void setOutboundSAMLMessageIssueInstant(DateTime instant) {
	}

	public void setOutboundSAMLMessageSigningCredential(Credential credential) {
	}

	public void setOutboundSAMLProtocol(String protocol) {
	}

	public void setPeerEntityEndpoint(Endpoint endpoint) {
	}

	public void setPeerEntityId(String id) {
	}

	public void setPeerEntityMetadata(EntityDescriptor metadata) {
	}

	public void setPeerEntityRole(QName role) {
	}

	public void setPeerEntityRoleMetadata(RoleDescriptor role) {
	}

	public void setRelayState(String relayState) {
	}

	public void setSubjectNameIdentifier(SAMLObject identifier) {
	}

	public String getCommunicationProfileId() {
		return null;
	}

	public XMLObject getInboundMessage() {
		return null;
	}

	public String getInboundMessageIssuer() {
		return serviceProvider;
	}

	public InTransport getInboundMessageTransport() {
		return null;
	}

	public XMLObject getOutboundMessage() {
		return null;
	}

	public String getOutboundMessageIssuer() {
		return null;
	}

	public OutTransport getOutboundMessageTransport() {
		return null;
	}

	public SecurityPolicyResolver getSecurityPolicyResolver() {
		return null;
	}

	public boolean isIssuerAuthenticated() {
		return false;
	}

	public void setCommunicationProfileId(String id) {
		
	}

	public void setInboundMessage(XMLObject message) {
		
	}

	public void setInboundMessageIssuer(String issuer) {
		
	}

	public void setInboundMessageTransport(InTransport transport) {
		
	}

	public void setOutboundMessage(XMLObject message) {
		
	}

	public void setOutboundMessageIssuer(String issuer) {
		
	}

	public void setOutboundMessageTransport(OutTransport transport) {
		
	}

	public void setSecurityPolicyResolver(SecurityPolicyResolver resolver) {
		
	}

	public HandlerChainResolver getPreSecurityInboundHandlerChainResolver() {
		return null;
	}

	public void setPreSecurityInboundHandlerChainResolver(HandlerChainResolver newHandlerChainResolver) {
		
	}

	public HandlerChainResolver getPostSecurityInboundHandlerChainResolver() {
		return null;
	}

	public void setPostSecurityInboundHandlerChainResolver(HandlerChainResolver newHandlerChainResolver) {
		
	}

	public HandlerChainResolver getOutboundHandlerChainResolver() {
		return null;
	}

	public void setOutboundHandlerChainResolver(HandlerChainResolver newHandlerChainResolver) {
		
	}

	public ProfileConfiguration getProfileConfiguration() {
		return null;
	}

	public RelyingPartyConfiguration getRelyingPartyConfiguration() {
		return null;
	}

	public Session getUserSession() {
		return null;
	}

	public void setProfileConfiguration(ProfileConfiguration configuration) {
		
	}

	public void setRelyingPartyConfiguration(RelyingPartyConfiguration configuration) {
		
	}

	public void setUserSession(Session session) {
		
	}

	public Collection getReleasedAttributes() {
		return null;
	}

	public void setReleasedAttributes(Collection attributeIds) {
		
	}

	public Collection<String> getRequestedAttributesIds() {
		return null;
	}

	public void setRequestedAttributes(Collection<String> ids) {
		
	}

	public Map<String, BaseAttribute> getAttributes() {
		return null;
	}

	public void setAttributes(Map<String, BaseAttribute> attributes) {
		
	}

	public String getPrincipalAuthenticationMethod() {
		return authenticationMethod;
	}

	public String getPrincipalName() {
		return user;
	}

	public void setPrincipalAuthenticationMethod(String method) {
	}

	public void setPrincipalName(String name) {
	}

}
