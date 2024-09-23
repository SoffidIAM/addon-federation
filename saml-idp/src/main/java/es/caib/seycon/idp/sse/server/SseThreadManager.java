package es.caib.seycon.idp.sse.server;

import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.server.handler.ContextHandler.Context;

import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.api.SseReceiverMethod;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;
import com.soffid.iam.api.PagedResult;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SseThreadManager extends Thread {
	Log log = LogFactory.getLog(getClass());
	
	Map<String, SsePushSender> threads = new HashMap<>();

	private ServletContext servletContext;
	public SseThreadManager(Context servletContext) {
		this.servletContext = servletContext;
	}
	
	public void run() {
		while (true) {
			SharedSignalEventsService svc;
			try {
				svc = new RemoteServiceLocator().getSharedSignalEventsService();
				PagedResult<SseReceiver> receivers = svc.findReceiver(null, null, null, null);
				List<String> l = new LinkedList<String>(threads.keySet());
				for (SseReceiver receiver: receivers.getResources()) 
				{
					if (! receiver.isPause() && receiver.getMethod() == SseReceiverMethod.PUSH) {
						SsePushSender thread = threads.get(receiver.getName());
						if (thread == null) {
							thread = new SsePushSender(receiver, servletContext);
							thread.start();
							threads.put(receiver.getName(), thread);
						}
						else
						{
							thread.setReceiver(receiver);
						}
						l.remove(receiver.getName());
					}
				}
				for (String name: l) {
					SsePushSender thread = threads.get(name);
					if (thread != null) {
						thread.end();
						threads.remove(name);
					}
				}
			} catch (IOException | InternalErrorException e1) {
				log.warn("Error configuring sse receivers", e1);
			}
					
			try {
				Thread.sleep(10000);
			} catch (InterruptedException e) {
			}
		}
	}
}
