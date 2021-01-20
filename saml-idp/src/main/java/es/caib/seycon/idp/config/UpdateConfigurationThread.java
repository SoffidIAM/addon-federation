package es.caib.seycon.idp.config;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.util.Date;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederacioService;
import com.soffid.iam.service.AdditionalDataService;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.config.Config;
import es.caib.seycon.idp.client.ServerLocator;
import com.soffid.iam.sync.service.ServerService;
import com.soffid.iam.utils.Security;

public class UpdateConfigurationThread extends Thread {

    private EntityGroupMember egm;
    private Logger log;
	private IdpConfig cfg;
    public UpdateConfigurationThread(IdpConfig cfg, EntityGroupMember egm) {
        super();
        this.cfg = cfg;
        this.egm = egm;
        log = LoggerFactory.getLogger(UpdateConfigurationThread.class);
    }

    private File confDir;
    private ServerLocator serverLocator;
    long lastPolicyUpdate;
    long lastFederationUpdate;
    private boolean end = false;
    
    @Override
    public void run() {
        long l;
        do {
            
        	Security.nestedLogin(cfg.getSystem().getTenant(), "saml-configuration-thread", Security.ALL_PERMISSIONS);
            try {
                Thread.sleep(30000); /// 5 Minutos
                if (end) {
                    log.info("Exiting UpdateConfigurationThread");  //$NON-NLS-1$
                    return;
                }
                l = getLastFederationUpdate();
                if ( l > lastFederationUpdate)
                    generateRelyingParties();
                l = getLastPolicyUpdate();
                if (l > lastPolicyUpdate)
                {
                    generateAttributeFilter();
                    generateAttributeResolver();
                }
                cfg.updateFederationMember();
            } catch (Exception e) {
                log.warn("Error testing for policy/federation changes", e);  //$NON-NLS-1$
            } 
        } while (true);
        
    }

    public synchronized void doStart() throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException, SAXException, ParserConfigurationException, TransformerException {
        confDir = IdpConfig.getConfig().getConfDir();

        serverLocator = ServerLocator.getInstance();
        
        generateAttributeResolver();
        
        generateAttributeFilter();

        generateRelyingParties();

        start();
    }

    private long getLastUpdate (String attribute) throws NumberFormatException, InternalErrorException, IOException {
    	ServerService server = serverLocator.getRemoteServiceLocator().getServerService();
        String config = server.getConfig(attribute);
        if (config == null)
        	return 0;
        else
        	return Long.decode(config);
        
    }
    
    private FederacioService getFederacioService () throws IOException, InternalErrorException {
    	ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
    	Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
    	try {
	    	return new RemoteServiceLocator().getFederacioService();
	    } finally {
	    	Thread.currentThread().setContextClassLoader(oldClassLoader);
	    }

    }
    
	private void generateRelyingParties() throws SAXException, IOException,
			ParserConfigurationException, TransformerException,
			UnrecoverableKeyException, InvalidKeyException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException,
			NoSuchProviderException, SignatureException,
			InternalErrorException, FileNotFoundException {

		long l = getLastFederationUpdate();
		File f = new File(confDir, "relying-party-new.xml"); //$NON-NLS-1$
		FileOutputStream out = new FileOutputStream(f);
		RelyingPartyGenerator rpg = new RelyingPartyGenerator(
				getFederacioService(), egm);
		rpg.generate(out);
		out.close();
		File newFile = new File(confDir, "relying-party.xml");
		newFile.delete();
		f.renameTo(newFile); //$NON-NLS-1$

		ServerService server = serverLocator.getRemoteServiceLocator()
				.getServerService();
		String serverList = server.getConfig("seycon.server.list"); //$NON-NLS-1$
		if (serverList != null) {
			Config c = Config.getConfig();
			c.setServerList(serverList);
		}

		lastFederationUpdate = l;

		log.info("Updated relying-party.xml"); //$NON-NLS-1$
	}

    private long getLastFederationUpdate() throws InternalErrorException,
            IOException {
        long l = getLastUpdate("saml.federation.lastchange"); //$NON-NLS-1$
        log.info(String.format("SEU Federation time-stamp: %s", DateFormat.getDateTimeInstance().format(new Date(l)))); //$NON-NLS-1$
        return l;
    }

	private void generateAttributeResolver() throws IOException,
			InternalErrorException, SAXException, ParserConfigurationException,
			TransformerException, FileNotFoundException {

		long l = getLastPolicyUpdate();
		File f = new File(confDir, "attribute-resolver-new.xml"); //$NON-NLS-1$
		FileOutputStream out = new FileOutputStream(f);
		AttributeResolverGenerator afg = new AttributeResolverGenerator(
				getAdditionalDateService());
		afg.generate(out);
		out.close();
		File newFile = new File(confDir, "attribute-resolver.xml");
		newFile.delete();
		f.renameTo(newFile); //$NON-NLS-1$

		log.info("Updated attribute-resolver.xml"); //$NON-NLS-1$

		lastPolicyUpdate = l;
	}

	private AdditionalDataService getAdditionalDateService() throws IOException, InternalErrorException {
    	ClassLoader oldClassLoader = Thread.currentThread().getContextClassLoader();
    	Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
    	try {
	    	return new RemoteServiceLocator().getAdditionalDataService();
	    } finally {
	    	Thread.currentThread().setContextClassLoader(oldClassLoader);
	    }
	}

	private void generateAttributeFilter() throws IOException,
			InternalErrorException, SAXException, ParserConfigurationException,
			TransformerException, FileNotFoundException {

		long l = getLastPolicyUpdate();
		File f = new File(confDir, "attribute-filter-new.xml"); //$NON-NLS-1$
		FileOutputStream out = new FileOutputStream(f);
		AttributeFilterGenerator afg = new AttributeFilterGenerator(
				getFederacioService());
		afg.generate(out);
		out.close();
		File newFile = new File(confDir, "attribute-filter.xml");
		newFile.delete();
		f.renameTo(newFile); //$NON-NLS-1$

		log.info("Updated attribute-filter.xml"); //$NON-NLS-1$

		lastPolicyUpdate = l;
	}

    private long getLastPolicyUpdate() throws InternalErrorException,
            IOException {
        Long l = getLastUpdate("saml.policy.lastchange"); //$NON-NLS-1$
        log.info(String.format("SEU Policy time-stamp: %s", DateFormat.getDateTimeInstance().format(new Date(l)))); //$NON-NLS-1$
        return l.longValue();
    }

    public void end() {
        end  = true;
        interrupt();
        interrupt();
        interrupt();
        try {
            join();
        } catch (InterruptedException e) {
        }
    }

}
