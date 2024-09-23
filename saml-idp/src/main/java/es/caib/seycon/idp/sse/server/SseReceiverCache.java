package es.caib.seycon.idp.sse.server;

import java.io.IOException;
import java.util.Date;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SseReceiverCache {
	Log log = LogFactory.getLog(getClass());
	
	static SseReceiverCache cache = new SseReceiverCache();
	public static SseReceiverCache instance() {
		return cache;
	}
	
	Hashtable<String, SseReceiver> receivers = new Hashtable<>();
	Hashtable<String, SseReceiver> receiversByName = new Hashtable<>();
	List<SseReceiver> receiverList = new LinkedList<>();
	long timestamp = 0;
	boolean refreshing = false;
	
	private synchronized void refresh () throws IOException, InternalErrorException {
		if (timestamp + 30000 < System.currentTimeMillis() && !refreshing) {
			refreshing = true;
			new Thread (() -> {
				try {
			    	refreshNow();
				} catch (Exception e) {
					log.warn("Error fetching list of SSE receivers", e);
				} finally {
					refreshing = false;
				}
			}).start();
		}
	}

	protected void refreshNow() throws IOException, InternalErrorException {
		SharedSignalEventsService sseService = new RemoteServiceLocator().getSharedSignalEventsService();
		receiverList = sseService.findReceiver(null, null, null, null).getResources();
		receivers = new Hashtable<>();
		receiversByName = new Hashtable<>();
		timestamp = System.currentTimeMillis();
	}

	public SseReceiver findBySecret(String auth) throws IOException, InternalErrorException {
		refresh();
		if (auth.toLowerCase().startsWith("bearer"))
			auth = auth.substring(7);
		SseReceiver r = receivers.get(auth);
		if (r != null) {
			return (validateTokenExpiration(r)) ? r : null;
		}
		int step = 0;
		do {
			for (SseReceiver r2: receiverList) {
				if (r2.getToken() != null && r2.getToken().validate(auth)) {
					receivers.put(auth, r2);
					return (validateTokenExpiration(r2)) ? r2 : null;
				}
			}
			if (step == 0)
				refreshNow();
			step ++;
		} while (step < 2);
		return null;
	}

	public boolean validateTokenExpiration(SseReceiver r) {
		if (r.getExpiration()==null)
			return true;
		Date now = new Date();
		return (now.getTime()<r.getExpiration().getTime());
	}

	public SseReceiver findByName(String receiver) throws IOException, InternalErrorException {
		refresh();
		SseReceiver r = receiversByName.get(receiver);
		if (r != null) 
			return r;
		int step = 0;
		do {
			for (SseReceiver r2: receiverList) {
				if (receiver.equals(r2.getName())) {
					receiversByName.put(r2.getName(), r2);
					return r2;
				}
			}
			if (step == 0)
				refreshNow();
			step ++;
		} while (step < 2);
		return null;
	}
}
