package es.caib.seycon.idp.sse.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.servlet.ServletContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.server.handler.ContextHandler.Context;
import org.json.JSONObject;
import org.json.JSONTokener;

import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class SsePushSender extends Thread {
	Log log = LogFactory.getLog(getClass());
	private SseReceiver receiver;
	private boolean end;
	private ServletContext servletContext;

	public SsePushSender(SseReceiver receiver, ServletContext servletContext2) {
		this.receiver = receiver;
		this.servletContext = servletContext2;
		end = false;
	}

	public void end() {
		end = true;
		this.interrupt();
	}

	@Override
	public void run() {
		while (!end) {
			try {
				SharedSignalEventsService svc = new RemoteServiceLocator().getSharedSignalEventsService();
				List<SseEvent> events = svc.fetchEvents(receiver, null);
				SseSender s = new SseSender();
				for (SseEvent event: events) {
					if (s.applies (receiver, event, servletContext)) {
						String data = s.generateSET(event, servletContext);
						send(data);
					}
					svc.removeEvent(event.getId());
				}
			} catch (Exception e) {
				log.warn("Error sending push notifications to "+receiver.getName(), e);
			}
			try {
				Thread.sleep(10000);
			} catch (InterruptedException e) {
			}
		}
	}

	private void send(String data) throws IOException, InternalErrorException {
		URL url = new URL(receiver.getUrl());
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setDoInput(true);
		conn.setDoOutput(true);
		if (receiver.getAuthorizationHeader() != null && ! receiver.getAuthorizationHeader().trim().isEmpty())
			conn.addRequestProperty("Autholization", receiver.getAuthorizationHeader());
		conn.addRequestProperty("Accept", "application/json");
		conn.addRequestProperty("Content-Type", "application/secevent+jwt");
		OutputStream out = conn.getOutputStream();
		out.write(data.getBytes(StandardCharsets.UTF_8));
		out.close();
		
		int status = conn.getResponseCode();
		
		if (status != 200 && status != 202) {
			String ct = conn.getHeaderField("Content-Type");
			final InputStream in = conn.getInputStream();
			if (ct != null && ct.equals("application-json")) {
				JSONObject o = new JSONObject(new JSONTokener(in));
				in.close();
				log.warn("Error sending event to "+receiver.getUrl()+". "+
						o.optString("err")+": "+o.optString("description"));
			}
			else {
				InputStream error = conn.getErrorStream();
				if (error != null)
					error.close();
				else
					in.close();
				throw new IOException("Error reading response from "+receiver.getUrl()+". Error "+status);
			}
		}
	}

	public void setReceiver(SseReceiver receiver) {
		this.receiver = receiver;
	}
	

}
