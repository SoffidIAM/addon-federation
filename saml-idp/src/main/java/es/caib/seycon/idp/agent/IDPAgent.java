package es.caib.seycon.idp.agent;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Date;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.User;
import com.soffid.iam.federation.idp.Main;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.agent.Agent;
import com.soffid.iam.sync.intf.AccessLogMgr;
import com.soffid.iam.sync.intf.UserMgr;

import es.caib.seycon.idp.shibext.LogRecorder;
import es.caib.seycon.idp.sse.server.Events;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.LogEntry;

public class IDPAgent extends Agent implements AccessLogMgr, UserMgr {
	SharedSignalEventsService svc;
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
		                    main = createMain();
		                    name = newName;
		                    main.start(newName, getSystem());
		                }
		            } catch (Exception e) {
		            	log.warn("Error starting IDP", e);
		            	try {
		            		stopMain();
		            	} catch (Exception e2) {}
		            	name = null; 
		            	main = null;
		                throw new InternalErrorException("Error starting IDP", e); //$NON-NLS-1$
		            }
		        }
        	}
        }
        svc = new RemoteServiceLocator().getSharedSignalEventsService();
    }

	protected Main createMain() {
		return new Main();
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

	@Override
	public void removeUser(String arg0) throws RemoteException, InternalErrorException {
	}

	@Override
	public void updateUser(Account arg0) throws RemoteException, InternalErrorException {
		SseEvent ev = new SseEvent();
		ev.setReceiver("-");
		ev.setType(Events.CAEP_TOKEN_CLAIMS_CHANGE);
		ev.setAccountName(arg0.getName());
		ev.setAccountSystem(arg0.getSystem());
		ev.setDate(new Date());
		svc.addEventTemplate(ev);
	}

	@Override
	public void updateUser(Account arg0, User arg1) throws RemoteException, InternalErrorException {
		SseEvent ev = new SseEvent();
		ev.setReceiver("-");
		ev.setType(Events.CAEP_TOKEN_CLAIMS_CHANGE);
		ev.setUser(arg1.getUserName());
		ev.setAccountName(arg0.getName());
		ev.setAccountSystem(arg0.getSystem());
		ev.setDate(new Date());
		svc.addEventTemplate(ev);
	}

	@Override
	public void updateUserPassword(String arg0, User arg1, Password arg2, boolean arg3)
			throws RemoteException, InternalErrorException {
	}

	@Override
	public boolean validateUserPassword(String arg0, Password arg1) throws RemoteException, InternalErrorException {
		return false;
	}

}
