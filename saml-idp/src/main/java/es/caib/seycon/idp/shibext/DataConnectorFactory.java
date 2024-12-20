package es.caib.seycon.idp.shibext;

import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorFactoryBean;;

public class DataConnectorFactory extends BaseDataConnectorFactoryBean {

    @Override
    public Class getObjectType() {
        return DataConnector.class;
    }

    @Override
    protected Object createInstance() throws Exception {
        DataConnector dc = new DataConnector();
        populateDataConnector(dc);
        return dc;
    }

}
