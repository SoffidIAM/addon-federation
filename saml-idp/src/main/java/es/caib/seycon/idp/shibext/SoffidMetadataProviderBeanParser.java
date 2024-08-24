package es.caib.seycon.idp.shibext;

import java.util.List;

import javax.xml.namespace.QName;

import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.SpringConfigurationUtils;
import edu.internet2.middleware.shibboleth.common.config.metadata.AbstractReloadingMetadataProviderBeanDefinitionParser;
import edu.internet2.middleware.shibboleth.common.config.metadata.MetadataNamespaceHandler;

/** Parser for {@link ResourceBackedMetadataProvider} definitions. */
public class SoffidMetadataProviderBeanParser extends
        AbstractReloadingMetadataProviderBeanDefinitionParser {

    /** Schema type name. */
    public static final QName TYPE_NAME = new QName(MetadataNamespaceHandler.NAMESPACE,
            "SoffidMetadataProvider");

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return SoffidMetadataProvider.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, ParserContext parserContext, BeanDefinitionBuilder builder) {
        super.doParse(config, parserContext, builder);
    }
}