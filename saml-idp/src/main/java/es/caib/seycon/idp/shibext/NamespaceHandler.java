package es.caib.seycon.idp.shibext;

import org.springframework.beans.factory.xml.BeanDefinitionParser;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

public class NamespaceHandler extends BaseSpringNamespaceHandler {

    public static String NAMESPACE = "urn:soffid.com:shibboleth:2.0:resolver"; //$NON-NLS-1$

    public void init() {
        registerBeanDefinitionParser(DefinitionParser.SCHEMA_NAME,
                                    new DefinitionParser());
        registerBeanDefinitionParser(MazingerDefinitionParser.SCHEMA_NAME,
                new MazingerDefinitionParser());
        
        registerBeanDefinitionParser(SoffidSAML2SLOProfileHandlerBeanDefinitionParser.SCHEMA_TYPE,
                new SoffidSAML2SLOProfileHandlerBeanDefinitionParser());

        BeanDefinitionParser parser = new SoffidAttributeResolverBeanDefinitionParser();
        registerBeanDefinitionParser(SoffidAttributeResolverBeanDefinitionParser.SCHEMA_TYPE, parser);
        
    }
}
