package es.caib.seycon.idp.shibext;

import org.springframework.beans.factory.xml.BeanDefinitionParser;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class RelyingPartyNamespaceHandler extends BaseSpringNamespaceHandler {

    public static String NAMESPACE = "urn:soffid.com:shibboleth:2.0:relying-party"; //$NON-NLS-1$

    public void init() {
        registerBeanDefinitionParser(RelyingPartyConfigurationManagerBeanParser.TYPE_NAME, 
        		new RelyingPartyConfigurationManagerBeanParser());
    }
}
