package es.caib.seycon.idp.session;

import java.util.Date;

import edu.internet2.middleware.shibboleth.idp.session.Session;

public class SessionInfo {
    long sessionId;
    String sessionKey;
    String user;
    Session idpSession;
    Date creation;
    Date lastUpdate;
    String remoteIp;
    
    public String getRemoteIp() {
        return remoteIp;
    }
    public void setRemoteIp(String remoteIp) {
        this.remoteIp = remoteIp;
    }
    public String getUser() {
        return user;
    }
    public void setUser(String user) {
        this.user = user;
    }
    public Date getCreation() {
        return creation;
    }
    public void setCreation(Date creation) {
        this.creation = creation;
    }
    public Date getLastUpdate() {
        return lastUpdate;
    }
    public void setLastUpdate(Date lastUpdate) {
        this.lastUpdate = lastUpdate;
    }
    public long getSessionId() {
        return sessionId;
    }
    public void setSessionId(long sessionId) {
        this.sessionId = sessionId;
    }
    public String getSessionKey() {
        return sessionKey;
    }
    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }
    public Session getIdpSession() {
        return idpSession;
    }
    public void setIdpSession(Session idpSession) {
        this.idpSession = idpSession;
    }
    
    
}
