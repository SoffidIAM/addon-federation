package es.caib.seycon.idp.shibext;

import javax.xml.namespace.QName;

import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.service.AbstractReloadableServiceBeanDefinitionParser;

/** Parser for {@link ResourceBackedMetadataProvider} definitions. */
public class RelyingPartyConfigurationManagerBeanParser extends AbstractReloadableServiceBeanDefinitionParser {

    /** Schema type name. */
    public static final QName TYPE_NAME = new QName(RelyingPartyNamespaceHandler.NAMESPACE,
            "RelyingPartyConfigurationManager");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return RelyingPartyConfigurationManager.class;
    }

}