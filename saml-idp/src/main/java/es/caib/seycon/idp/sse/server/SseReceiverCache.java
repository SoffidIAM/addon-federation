package es.caib.seycon.idp.sse.server;

import java.io.IOException;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SseReceiverCache {
	Log log = LogFactory.getLog(getClass());
	
	static SseReceiverCache cache = new SseReceiverCache();
	public static SseReceiverCache instance() {
		return cache;
	}
	
	Hashtable<String, SseReceiver> receivers = new Hashtable<>();
	List<SseReceiver> receiverList = new LinkedList<>();
	long timestamp = 0;
	boolean refreshing = false;
	
	private synchronized void refresh () throws IOException, InternalErrorException {
		if (timestamp + 30000 < System.currentTimeMillis() && !refreshing) {
			refreshing = true;
			new Thread (() -> {
				try {
			    	SharedSignalEventsService sseService = new RemoteServiceLocator().getSharedSignalEventsService();
			    	receiverList = sseService.findReceiver(null, null, null, null).getResources();
			    	receivers = new Hashtable<>();
				} catch (Exception e) {
					log.warn("Error fetching list of SSE receivers", e);
				} finally {
					refreshing = false;
				}
			}).start();
		}
	}

	public SseReceiver findBySecret(String auth) throws IOException, InternalErrorException {
		refresh();
		SseReceiver r = receivers.get(auth);
		if (r != null) 
			return r;
		for (SseReceiver r2: receiverList) {
			if (r2.getToken() != null && r2.getToken().validate(auth)) {
				receivers.put(auth, r2);
				return r2;
			}
		}
		return null;
	}
}
