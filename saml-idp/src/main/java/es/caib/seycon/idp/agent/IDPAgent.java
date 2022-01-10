package es.caib.seycon.idp.agent;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Date;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.federation.idp.Main;
import com.soffid.iam.sync.agent.Agent;
import com.soffid.iam.sync.intf.AccessLogMgr;

import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.LogEntry;

public class IDPAgent extends Agent implements AccessLogMgr {

    static String name = null;
    static Main main = null;
    static Object lock = new Object();
    String newName;
    boolean dummy = false;

    public IDPAgent() {
        super();
    }

    public boolean isSingleton() 
    {
    	return true;
    }
    
    @Override
    public void init() throws Exception {
        super.init();
        newName = getSystem().getParam0();
        if (newName == null)
            throw new InternalErrorException("Missing idp publicId"); //$NON-NLS-1$
        
        dummy = true;
        for (FederationMember fm: 
        	new RemoteServiceLocator().getFederacioService().findFederationMemberByEntityGroupAndPublicIdAndTipus(null, newName, "I"))
        {
        	if (fm.getInternal() != null && fm.getInternal().booleanValue())
        	{
        		dummy = false;
		        synchronized (lock) {
		            try {
		            	log.info("Staring dispatcher "+newName); //$NON-NLS-1$
		                if (! newName.equals(name)) { 
		                	log.info ("Existing dispatcher was "+main); //$NON-NLS-1$
		                    if (main != null) {
		                        log.info("Stopping IDP {}", name, null); //$NON-NLS-1$
		                        stopMain();
		                    }
		                    if (name == null)
		                        log.info("Starting IDP {} (Previous {})", newName, name); //$NON-NLS-1$
		                    main = new Main();
		                    main.start(newName, getSystem());
		                    name = newName;
		                }
		            } catch (Exception e) {
		            	log.warn("Error starting IDP", e);
		            	try {
		            		stopMain();
		            	} catch (Exception e2) {}
		                throw new InternalErrorException("Error starting IDP", e); //$NON-NLS-1$
		            }
		        }
        	}
        }
    }

    private void stopMain() {
        try {
            main.stop();
            name = null;
            main = null;
        } catch (Exception e) {
            log.warn("Error stopping IDP", e); //$NON-NLS-1$
        }
    }

	public Collection<LogEntry> getLogFromDate(Date from)
			throws RemoteException, InternalErrorException {
		if (dummy)
			return null;
		else
			return LogRecorder.getInstance().getLogs(from);
	}

}
