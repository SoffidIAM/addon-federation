package es.caib.seycon.idp.shibext;

import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorBeanDefinitionParser;

public class MazingerDefinitionParser extends BaseDataConnectorBeanDefinitionParser {
    public static final QName SCHEMA_NAME = new QName(NamespaceHandler.NAMESPACE, "MazingerLookup"); //$NON-NLS-1$

    @Override
    protected void doParse(String pluginId, Element pluginConfig,
            Map<QName, List<Element>> pluginConfigChildren,
            BeanDefinitionBuilder pluginBuilder, ParserContext parserContext) {

        super.doParse(pluginId, pluginConfig, pluginConfigChildren, pluginBuilder,
                parserContext);
    }

    protected Class getBeanClass(Element element) {
        return MazingerConnectorFactory.class;
    }
}
