package es.caib.seycon.idp.server;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

import com.soffid.iam.api.Host;
import com.soffid.iam.api.Issue;
import com.soffid.iam.api.IssueHost;
import com.soffid.iam.api.IssueStatus;
import com.soffid.iam.api.IssueUser;
import com.soffid.iam.api.User;
import com.soffid.iam.federation.idp.RemoteServiceLocator;
import com.soffid.iam.sync.service.ServerService;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownHostException;

public class CreateIssueHelper {

	public static void globalFailedLogin(double pct) throws InternalErrorException, IOException {
		ServerService server = new RemoteServiceLocator().getServerService();
		Issue i = new Issue();
		i.setCreated(new Date());
		i.setStatus(IssueStatus.NEW);
		i.setType("global-failed-login");
		i.setFailedLoginPct(pct);
		server.registerIssue(i);
	}

	public static void robotLogin(String u, double pct, String hostId, String ip) throws InternalErrorException, IOException {
		ServerService server = new RemoteServiceLocator().getServerService();
		Issue i = new Issue();
		i.setCreated(new Date());
		i.setStatus(IssueStatus.NEW);
		i.setType("robot-login");
		i.setFailedLoginPct(pct);
		if (u != null) {
			IssueUser iu = new IssueUser();
			iu.setUserName(u);
			i.setUsers(Arrays.asList(iu));
		}

		IssueHost ih = new IssueHost();
		Host h;
		ih.setHostIp(ip);
		ih.setHostName(hostId);
		i.setHosts(Arrays.asList(ih));
		i.setHash(hostId);

		server.registerIssue(i);
	}

	public static void wrongUser(String u, String hostId, String ip) throws InternalErrorException, IOException {
		ServerService server = new RemoteServiceLocator().getServerService();
		Issue i = new Issue();
		i.setCreated(new Date());
		i.setStatus(IssueStatus.NEW);
		i.setType("login-not-recognized");
		IssueUser iu = new IssueUser();
		iu.setUserName(u);
		i.setUsers(Arrays.asList(iu));
		i.setHash(u);
		IssueHost ih = new IssueHost();
		Host h;
		ih.setHostIp(ip);
		ih.setHostName(hostId);
		i.setHosts(Arrays.asList(ih));

		server.registerIssue(i);
	}
}
