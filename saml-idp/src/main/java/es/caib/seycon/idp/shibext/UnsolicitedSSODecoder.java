package es.caib.seycon.idp.shibext;

import java.util.List;

import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class UnsolicitedSSODecoder extends edu.internet2.middleware.shibboleth.idp.profile.saml2.UnsolicitedSSODecoder {
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(UnsolicitedSSODecoder.class);


    /**
     * Constructor.
     * 
     * @param identifierGenerator the IdentifierGenerator instance to use.
     */
    @SuppressWarnings("unchecked")
    public UnsolicitedSSODecoder(IdentifierGenerator identifierGenerator) {
        super(identifierGenerator);
    }

    
    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    protected void doDecode(MessageContext messageContext) throws MessageDecodingException {
        super.doDecode(messageContext);
       
        HTTPInTransport transport = (HTTPInTransport) messageContext.getInboundMessageTransport();
        String nameFormat = DatatypeHelper.safeTrimOrNullString(transport.getParameterValue("nameFormat")); //$NON-NLS-1$
        if (nameFormat == null) {
            AuthnRequest req = (AuthnRequest) messageContext.getInboundMessage();
            String issuer = req.getIssuer().getValue();
            BasicSAMLMessageContext requestContext = (BasicSAMLMessageContext) messageContext;
            MetadataProvider mdp = requestContext.getMetadataProvider();
            try {
                EntityDescriptor ed = mdp.getEntityDescriptor(issuer);
                if (ed != null) {
                    SPSSODescriptor ssod = ed.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol"); //$NON-NLS-1$
                    if (ssod != null) {
                        List<NameIDFormat> formats = ssod.getNameIDFormats();
                        if (formats.size() == 1) {
                            nameFormat = formats.get(0).getFormat();
                        }
                    }
                }
            } catch (MetadataProviderException e) {
                log.warn(String.format("Error looking for %s metadata",issuer), e); //$NON-NLS-1$
            }
        }
        if (nameFormat != null) {
            XMLObject msg = messageContext.getInboundMessage();

            AuthnRequest req = (AuthnRequest) msg;
            req.getNameIDPolicy().setFormat(nameFormat);
        }

    }
}