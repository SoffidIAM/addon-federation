/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.soffid.iam.addons.federation.service.impl;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;

import javax.annotation.Nonnull;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.service.FederationService;

import es.caib.seycon.ng.exception.InternalErrorException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * A metadata provider that pulls metadata from a file on the local filesystem.
 * 
 * This metadata provider periodically checks to see if the read metadata file has changed. The delay between each
 * refresh interval is calculated as follows. If no validUntil or cacheDuration is present then the
 * {@link #getMaxRefreshDelay()} value is used. Otherwise, the earliest refresh interval of the metadata file is checked
 * by looking for the earliest of all the validUntil attributes and cacheDuration attributes. If that refresh interval
 * is larger than the max refresh delay then {@link #getMaxRefreshDelay()} is used. If that number is smaller than the
 * min refresh delay then {@link #getMinRefreshDelay()} is used. Otherwise the calculated refresh delay multiplied by
 * {@link #getRefreshDelayFactor()} is used. By using this factor, the provider will attempt to be refresh before the
 * cache actually expires, allowing a some room for error and recovery. Assuming the factor is not exceedingly close to
 * 1.0 and a min refresh delay that is not overly large, this refresh will likely occur a few times before the cache
 * expires.
 * 
 */
public class InternalMetadataResolver extends AbstractReloadingMetadataResolver {

    /** Class logger. */
    private final Log log = LogFactory.getLog(InternalMetadataResolver.class);

    /** The metadata file. */
    @Nonnull private File metadataFile;

	private FederationService svc;

    /**
     * Constructor.
     * 
     * @param metadata the metadata file
     * 
     * @throws ResolverException  this exception is no longer thrown
     */
    public InternalMetadataResolver() throws ResolverException {
    	super();
    	svc = (FederationService) ServiceLocator.instance().getService(FederationService.SERVICE_NAME);
    }

    /** {@inheritDoc} */
    @Override
    protected void doDestroy() {
        super.doDestroy();
    }
    
    /** {@inheritDoc} */
    @Override
    protected String getMetadataIdentifier() {
        return "Internal";
    }

    /** {@inheritDoc} */
    @Override
    protected byte[] fetchMetadata() throws ResolverException {
        try {
        	ByteArrayOutputStream out = new ByteArrayOutputStream();
        	PrintStream p = new PrintStream(out, true, "UTF-8");
	    	p.println("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
	    			+ "<EntitiesDescriptor Name=\"All Entities\" cacheDuration=\"PT10M\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n");
	    	
			for (FederationMember member: svc.findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "I")) {
				if (member.getClasse().equals("I") &&  member.getIdpType() == IdentityProviderType.SOFFID) {
					p.println(member.getMetadades());
				}
			}
	    	p.println("</EntitiesDescriptor>");
	    	p.close();
	    	return out.toByteArray();
        } catch (final IOException | InternalErrorException e) {
            throw new ResolverException("Unable to read metadata", e);
        }
    }
    
}