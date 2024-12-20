package es.caib.seycon.idp.shibext;

import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorFactoryBean;;

public class MazingerConnectorFactory extends BaseDataConnectorFactoryBean {

    @Override
    public Class getObjectType() {
        return MazingerConnector.class;
    }

    @Override
    protected Object createInstance() throws Exception {
        MazingerConnector dc = new MazingerConnector();
        populateDataConnector(dc);
        return dc;
    }

}
