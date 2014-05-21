package es.caib.seycon.idp.shibext;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.ProfileHandlerNamespaceHandler;
import edu.internet2.middleware.shibboleth.idp.config.profile.saml2.SAML2SLOProfileHandlerBeanDefinitionParser;

public class SoffidSAML2SLOProfileHandlerBeanDefinitionParser extends
		SAML2SLOProfileHandlerBeanDefinitionParser {
    /** Schema type. */
    public static final QName SCHEMA_TYPE =
            new QName(ProfileNamespaceHandler.NAMESPACE, "SAML2SLO");


    /** {@inheritDoc} */
    @Override
    protected Class getBeanClass(Element arg0) {
        return SoffidSLOProfileHandler.class;
    }

}
