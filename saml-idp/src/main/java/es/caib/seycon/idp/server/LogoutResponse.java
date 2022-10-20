package es.caib.seycon.idp.server;

import java.util.List;

public class LogoutResponse {
	List<FrontLogoutRequest> frontRequests;
	List<String> failedLogouts;
	public List<FrontLogoutRequest> getFrontRequests() {
		return frontRequests;
	}
	public void setFrontRequests(List<FrontLogoutRequest> frontRequests) {
		this.frontRequests = frontRequests;
	}
	public List<String> getFailedLogouts() {
		return failedLogouts;
	}
	public void setFailedLogouts(List<String> failedLogouts) {
		this.failedLogouts = failedLogouts;
	}
}
