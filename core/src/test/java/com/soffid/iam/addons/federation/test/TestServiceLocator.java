// license-header java merge-point
//
// Attention: Generated code! Do not modify by hand!
// Generated by: SpringServiceLocator.vsl in andromda-spring-cartridge.
//
package com.soffid.iam.addons.federation.test;

import java.io.FileNotFoundException;
import java.io.IOException;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.config.Config;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.remote.RemoteServiceLocatorProxy;

/**
 * Locates and provides all available application services.
 */
public class TestServiceLocator
{
    static private com.soffid.iam.ServiceLocator baseServiceLocator = null;


    private TestServiceLocator()
    {
    }

    /**
     * Gets the shared instance of this Class
     *
     * @return the shared service locator instance.
     */
    public static final com.soffid.iam.ServiceLocator instance()
    {
        if (baseServiceLocator == null) {
            baseServiceLocator = com.soffid.iam.ServiceLocator.instance();
    		baseServiceLocator.init("testBeanRefFactory.xml", "beanRefFactory");
        }
        return baseServiceLocator;
    }

}