package es.caib.seycon.idp.shibext;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class ProfileNamespaceHandler extends BaseSpringNamespaceHandler {

    public static String NAMESPACE = "urn:soffid.com:shibboleth:2.0:idp:profile-handler"; //$NON-NLS-1$

    public void init() {
        registerBeanDefinitionParser(SoffidSAML2SLOProfileHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new SoffidSAML2SLOProfileHandlerBeanDefinitionParser());

        registerBeanDefinitionParser(SoffidSAML2SSOProfileHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new SoffidSAML2SSOProfileHandlerBeanDefinitionParser());
    }
}