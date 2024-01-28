package es.caib.seycon.idp.config;
//========================================================================
//Copyright (c) Webtide LLC
//------------------------------------------------------------------------
//All rights reserved. This program and the accompanying materials
//are made available under the terms of the Eclipse Public License v1.0
//and Apache License v2.0 which accompanies this distribution.
//
//The Eclipse Public License is available at 
//http://www.eclipse.org/legal/epl-v10.html
//
//The Apache License v2.0 is available at
//http://www.opensource.org/licenses/apache2.0.php
//
//You may elect to redistribute this code under either of these licenses. 
//========================================================================

import java.util.Base64;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.servlet.ServletRequest;

import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.LoginService;
import org.eclipse.jetty.security.SpnegoUserPrincipal;
import org.eclipse.jetty.server.UserIdentity;
import org.eclipse.jetty.util.component.AbstractLifeCycle;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.resource.Resource;

import com.soffid.iam.addons.federation.common.KerberosKeytab;
import com.soffid.iam.api.Account;
import com.soffid.iam.remote.RemoteServiceLocator;

public class CustomSpnegoLoginService extends AbstractLifeCycle implements LoginService
{
    protected IdentityService _identityService;// = new LdapIdentityService();
    protected String _name;
    org.apache.commons.logging.Log log = LogFactory.getLog(getClass());

    public CustomSpnegoLoginService()
    {
        
    }
    
    public CustomSpnegoLoginService( String name )
    {
        setName(name);
    }
    
    public String getName()
    {
        return _name;
    }

    public void setName(String name)
    {
        if (isRunning())
        {
            throw new IllegalStateException("Running");
        }
        
        _name = name;
    }
    
    
    @Override
    protected void doStart() throws Exception
    {
        super.doStart();
    }

    /**
     * username will be null since the credentials will contain all the relevant info
     */
    public UserIdentity login(String username, Object credentials, ServletRequest request)
    {
        String encodedAuthToken = (String)credentials;
        
        byte[] authToken = Base64.getDecoder().decode(encodedAuthToken);
        
        
        try {
        	log.info ("Received kerberos token "+credentials);
			for (KerberosKeytab keytab: IdpConfig.getConfig().getFederationMember().getKeytabs())
			{
				try {
					Account account = new RemoteServiceLocator().getServerService().parseKerberosToken(keytab.getDomain(), keytab.getPrincipal(), keytab.getKeyTab(), authToken);
					if (account != null)
					{
						log.info("SpnegoUserRealm: established a security context");
						log.info("Client Principal is: " + account);
						log.info("Server Principal is: " + keytab.getPrincipal());
						log.info("Client Default Role: " + keytab.getDomain());
						
						SpnegoPrincipal user = new SpnegoPrincipal(account);
						
						Subject subject = new Subject();
						subject.getPrincipals().add(user);
						
						return _identityService.newUserIdentity(subject,user, new String[]{keytab.getDomain(), "krblogin"});
					}
				} catch (Exception e) {
					log.info("Error validating token against "+keytab.getDomain()+": "+e.toString());
				}
			}
		} catch (Exception e) {
            log.warn(e);
		}
        
        return null;
    }

    public boolean validate(UserIdentity user)
    {
        return false;
    }

    public IdentityService getIdentityService()
    {
        return _identityService;
    }

    public void setIdentityService(IdentityService service)
    {
        _identityService = service;
    }

	public void logout(UserIdentity user) {
	}

}
