package es.caib.seycon.idp.shibext;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.idp.config.profile.saml2.SAML2SSOProfileHandlerBeanDefinitionParser;

public class SoffidSAML2SSOProfileHandlerBeanDefinitionParser extends
		SAML2SSOProfileHandlerBeanDefinitionParser {
    /** Schema type. */
    public static final QName SCHEMA_TYPE =
            new QName(ProfileNamespaceHandler.NAMESPACE, "SAML2SSO");


    /** {@inheritDoc} */
    @Override
    protected Class getBeanClass(Element arg0) {
        return SoffidSSOProfileHandler.class;
    }

}
