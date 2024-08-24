
package es.caib.seycon.idp.shibext;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.xml.namespace.QName;

import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.BaseMetadataProvider;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ObservableMetadataProvider;
import org.opensaml.util.resource.Resource;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.soffid.iam.utils.Security;

import es.caib.seycon.ng.exception.InternalErrorException;

/**
 * A metadata provider that reads metadata from a {#link {@link Resource}.
 * 
 * @since 2.2
 */
public class SoffidMetadataProvider extends BaseMetadataProvider implements ObservableMetadataProvider {
	org.opensaml.xml.parse.ParserPool parser;
	
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ChainingMetadataProvider.class);

    /** List of registered observers. */
    private List<Observer> observers;

    /** Registered providers. */
    private Map<String,TenantMetadataProvider> providers;

    /** Lock used to block reads during write and vice versa. */
    private ReadWriteLock providerLock;

    /** Constructor. */
    public SoffidMetadataProvider() {
        super();
        observers = new CopyOnWriteArrayList<Observer>();
        providers = new HashMap<>();
        providerLock = new ReentrantReadWriteLock(true);
        parser = new BasicParserPool();
    }

    /** {@inheritDoc} */
    public void setRequireValidMetadata(boolean requireValidMetadata) {
        super.setRequireValidMetadata(requireValidMetadata);

        Lock writeLock = providerLock.writeLock();
        writeLock.lock();
        try {
            for (TenantMetadataProvider provider : providers.values()) {
                provider.setRequireValidMetadata(requireValidMetadata);
            }
        } finally {
            writeLock.unlock();
        }
    }

    /** {@inheritDoc} */
    public MetadataFilter getMetadataFilter() {
        log.warn("Attempt to access unsupported MetadataFilter property on ChainingMetadataProvider");
        return null;
    }

    /** {@inheritDoc} */
    public void setMetadataFilter(MetadataFilter newFilter) throws MetadataProviderException {
        throw new UnsupportedOperationException("Metadata filters are not supported on ChainingMetadataProviders");
    }

    /**
     * Gets the metadata from every registered provider and places each within a newly created EntitiesDescriptor.
     * 
     * {@inheritDoc}
     */
    public XMLObject getMetadata() throws MetadataProviderException {
		TenantMetadataProvider provider = getCurrentTenantProvider();
        return provider.getMetadata();
    }

	public TenantMetadataProvider getCurrentTenantProvider() throws MetadataProviderException {
		TenantMetadataProvider provider = null;
		String tenant = null;
		try {
			tenant = Security.getCurrentTenantName();
			provider = providers.get(tenant);
			if (provider == null)
			{
				provider = generateTenantMetadata(tenant);
			} else {
				provider.mayRefresh();
			}
		} catch (InternalErrorException e) {
			throw new MetadataProviderException("Cannot get tenant "+tenant+" metadata", e);
		} catch (IOException e) {
			throw new MetadataProviderException("Cannot get tenant "+tenant+" metadata", e);
		}
		return provider;
	}


    private TenantMetadataProvider generateTenantMetadata(String tenant) throws MetadataProviderException {
    	TenantMetadataProvider tdp = new TenantMetadataProvider(tenant);
    	tdp.setParserPool(parser);
    	tdp.initialize();
    	tdp.refresh();
    	providers.put(tenant, tdp);
    	return tdp;
	}

	/** {@inheritDoc} */
    public EntitiesDescriptor getEntitiesDescriptor(String name) throws MetadataProviderException {
		TenantMetadataProvider provider = getCurrentTenantProvider();
		return provider.getEntitiesDescriptor(name);
    }

    /** {@inheritDoc} */
    public EntityDescriptor getEntityDescriptor(String entityID) throws MetadataProviderException {
		TenantMetadataProvider provider = getCurrentTenantProvider();
		log.info("Searching for "+entityID+" in "+provider.getMetadataIdentifier());
		return provider.getEntityDescriptor(entityID);
    }

    /** {@inheritDoc} */
    public List<RoleDescriptor> getRole(String entityID, QName roleName) throws MetadataProviderException {
		TenantMetadataProvider provider = getCurrentTenantProvider();
		log.info("Searching role "+roleName+" for "+entityID+" in "+provider.getMetadataIdentifier());
		return provider.getRole(entityID, roleName);
    }

    /** {@inheritDoc} */
    public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol)
            throws MetadataProviderException {
		TenantMetadataProvider provider = getCurrentTenantProvider();
		log.info("Searching role "+roleName+" for "+entityID+" in "+provider.getMetadataIdentifier()+" Protocol "+supportedProtocol);
		return provider.getRole(entityID, roleName, supportedProtocol);
    }

    /** {@inheritDoc} */
    public List<Observer> getObservers() {
        try {
			return getCurrentTenantProvider().getObservers();
		} catch (MetadataProviderException e) {
			throw new RuntimeException(e);
		}
    }
    
    /** {@inheritDoc} */
    public synchronized void destroy() {
        super.destroy();
        
        for(TenantMetadataProvider provider : providers.values()){
        	provider.destroy();
        }
        
        providers.clear();
        observers = Collections.emptyList();
    }

}