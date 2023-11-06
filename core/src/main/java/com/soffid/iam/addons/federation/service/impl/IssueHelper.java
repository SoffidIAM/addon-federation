package com.soffid.iam.addons.federation.service.impl;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;

import com.soffid.iam.api.Host;
import com.soffid.iam.api.Issue;
import com.soffid.iam.api.IssueHost;
import com.soffid.iam.api.IssueStatus;
import com.soffid.iam.api.IssueUser;
import com.soffid.iam.api.User;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.service.IssueService;
import com.soffid.iam.sync.service.ServerService;

import es.caib.seycon.ng.exception.InternalErrorException;

public class IssueHelper {

	public static void fromDifferentCountry(Long userId, String country) throws InternalErrorException, IOException {
		IssueService svc = com.soffid.iam.ServiceLocator.instance().getIssueService();
		Issue i = new Issue();
		i.setCreated(new Date());
		i.setStatus(IssueStatus.NEW);
		i.setType("login-different-country");
		IssueUser iu = new IssueUser();
		iu.setUserId(userId);
		i.setUsers(Arrays.asList(iu));
		i.setCountry(country);
		svc.createInternalIssue(i);
	}

	public static void fromNewHost(Long userId, Host host) throws InternalErrorException {
		IssueService svc = com.soffid.iam.ServiceLocator.instance().getIssueService();
		Issue i = new Issue();
		i.setCreated(new Date());
		i.setStatus(IssueStatus.NEW);
		i.setType("login-from-new-device");
		IssueUser iu = new IssueUser();
		iu.setUserId(userId);
		i.setUsers(Arrays.asList(iu));
		
		if (host != null) {
			IssueHost ih = new IssueHost();
			ih.setHostId(host.getId());
			ih.setHostName(host.getName());
			ih.setHostIp(host.getIp());
			i.setHosts(Arrays.asList(ih));
		}
		svc.createInternalIssue(i);
	}

	public static void deviceCertificateBorrowed(Host host1, Host host2) throws InternalErrorException, IOException {
		IssueService svc = com.soffid.iam.ServiceLocator.instance().getIssueService();
		Issue i = new Issue();
		i.setCreated(new Date());
		i.setStatus(IssueStatus.NEW);
		i.setType("device-certificate-borrowed");
		IssueHost iu = new IssueHost();
		iu.setHostId(host1.getId());
		IssueHost iu2 = new IssueHost();
		iu2.setHostId(host2.getId());
		i.setHosts(Arrays.asList(iu));
		svc.createInternalIssue(i);
	}

}
