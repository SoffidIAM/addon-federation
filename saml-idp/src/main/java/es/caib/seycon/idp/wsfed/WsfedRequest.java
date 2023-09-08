package es.caib.seycon.idp.wsfed;

import com.soffid.iam.addons.federation.common.FederationMember;

public class WsfedRequest {
	String type;
	String publicId;
	private String state;
	private FederationMember federationMember;
	private String replyUrl;
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getPublicId() {
		return publicId;
	}
	public void setPublicId(String publicId) {
		this.publicId = publicId;
	}
	public void setState(String parameter) {
		this.state = parameter;
	}
	public String getState() {
		return state;
	}
	public void setFederationMember(FederationMember fm) {
		this.federationMember = fm;
	}
	public FederationMember getFederationMember() {
		return federationMember;
	}
	public void setReplyUrl(String replyUrl) {
		this.replyUrl = replyUrl;
	}
	public String getReplyUrl() {
		return replyUrl;
	}
}
