package es.caib.seycon.idp.sse.server;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.servlet.ServletContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.jetty.server.handler.ContextHandler.Context;
import org.json.JSONObject;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.soffid.iam.addons.federation.api.SseEvent;
import com.soffid.iam.addons.federation.api.SseReceiver;
import com.soffid.iam.addons.federation.api.SubjectFormatEnumeration;
import com.soffid.iam.addons.federation.api.SubjectSourceEnumeration;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.SharedSignalEventsService;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.User;
import com.soffid.iam.api.UserAccount;
import com.soffid.iam.interp.Evaluator;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class SseSender {
	Log log = LogFactory.getLog(getClass());
	private SharedSignalEventsService sseService;
	private ExecutorService executor;
	
	protected SseSender () throws IOException, InternalErrorException {
		sseService = new RemoteServiceLocator()
				.getSharedSignalEventsService();
		
		executor = Executors.newSingleThreadExecutor();

	}
	
	static SseSender cache = null;
	public static SseSender instance() throws IOException, InternalErrorException {
		if (cache == null)
			cache = new SseSender();
		return cache;
	}

	public void postMessage(SseEvent event) throws IOException, InternalErrorException {
		SseReceiver receiver = SseReceiverCache.instance().findByName(event.getReceiver());
		if (receiver != null && receiver.getEvents().contains(event.getType())) {
			sseService.addEvent(event);
		}
	}

	public String generateSET(SseEvent event, ServletContext servletContext) throws Exception {
		IdpConfig c = IdpConfig.getConfig();
		
		SseReceiver r = SseReceiverCache.instance().findByName(event.getReceiver());
		if (r == null)
			return null;

		JSONObject e = serializeEvent(r, event, r.getServiceProvider(), servletContext);
		KeyPair keyPair = c.getKeyPair();
		
		JSONObject s = serializeSubject(r, event, r.getServiceProvider(), servletContext);

		Algorithm algorithmRS = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());

		String jwt = JWT.create().withAudience(event.getReceiver())
		.withIssuedAt(new Date())
		.withIssuer(r.getIdentityProvider())
		.withClaim("events", e.toMap())
		.withClaim("sub_id", s.toMap())
		.withClaim("iat", event.getDate().getTime()/1000 )
		.withJWTId(event.getId().toString())
		.withKeyId(c.getHostName())
		.sign(algorithmRS);
		return jwt;
	}


	private JSONObject serializeEvent(SseReceiver r, SseEvent event, String serviceProvider, ServletContext servletContext) throws Exception {
		JSONObject o = new JSONObject();
		JSONObject o2 = new JSONObject();
		Account[] account = {null};
		User[] user = {null};
		if (event.getSubject() == null) {
			calculateSubject(event, r, account, user, servletContext);
		}
		o2 = serializeSubject(r, event, serviceProvider, servletContext);
		o.put(event.getType(), o2);
		return o;
	}

	private JSONObject serializeSubject(SseReceiver r, SseEvent event, String serviceProvider, ServletContext servletContext) throws Exception {
		JSONObject o2 = new JSONObject();
		if (event.getType().equals(Events.VERIFY_SSE) || event.getType().equals(Events.VERIFY_SSF)) {
			o2.put("state", event.getSubject());
		} else if (event.getType().endsWith(Events.CAEP_SESSION_REVOKED)) {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
		} else if (event.getType().endsWith(Events.CAEP_TOKEN_CLAIMS_CHANGE)) {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
			JSONObject claims = new JSONObject();
			try {
				TokenInfo t = new TokenInfo();
				t.setAuthentication(System.currentTimeMillis());
				t.setAuthenticationMethod("P");
				t.setCreated(System.currentTimeMillis());
				t.setExpires(System.currentTimeMillis());
				t.setUser(event.getAccountName());
				final OpenIdRequest request = new OpenIdRequest();
				t.setRequest(request);
				if (r.getServiceProvider() == null)
					request.setFederationMember(IdpConfig.getConfig().getFederationMember());
				else
					request.setFederationMember(IdpConfig.getConfig().getFederationService().findFederationMemberByPublicId(r.getServiceProvider()));

				for (Entry<String, Object> entry: new UserAttributesGenerator().generateAttributes(servletContext, t, true, false, false).entrySet()) {
					claims.put(entry.getKey(), entry.getValue());
				}
			} catch (AttributeResolutionException e) {
				log.warn("Error resolving attributes", e);
			} catch (AttributeFilteringException e) {
				log.warn("Error filtering attributes", e);
			} catch (InternalErrorException e) {
				log.warn("Error evaluating claims", e);
			} catch (Exception e) {
				log.warn("Error generating response", e);
			}
			o2.put("claims", claims);
		} else if (event.getType().endsWith(Events.CAEP_CREDENTIAL_CHANGE)) {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
			o2.put("x509_issuer", event.getX509Issuer());
			o2.put("x509_serial", event.getX509Serial());
			o2.put("credential_type", event.getCredentialType());
			o2.put("change_type", event.getChangeType());
			o2.put("fido2_aaguid", event.getFido2aaGuid());
			o2.put("friendly_name", event.getFriendlyName());
		} else if (event.getType().endsWith(Events.CAEP_ASSURANCE_LEVEL_CHANGE)) {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
			o2.put("current_level", event.getCurrentLevel());
			o2.put("previous_level", event.getPreviousLevel());
			o2.put("initiating_entity", "user");
			o2.put("change_direction",event.getPreviousLevel() == null ? "increase" :
					event.getPreviousLevel().compareTo(event.getCurrentLevel() ) < 0 ? "increase":
					"decrease");
		} else if (event.getType().endsWith(Events.CAEP_DEVICE_COMPLIANCE_CHANGE)) {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
			o2.put("current_status", event.getCurrentLevel());
			o2.put("previous_status", event.getPreviousLevel());
		} else if (event.getType().endsWith(Events.RISC_IDENTIFIER_CHANGED)) {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
			o2.put("current_status", event.getCurrentLevel());
			o2.put("previous_status", event.getPreviousLevel());
		} else if (event.getType().endsWith(Events.RISC_CREDENTIAL_COMPROMISED)) {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
			o2.put("credential_type", event.getCredentialType());
		} else if (event.getType().endsWith(Events.SOFFID_AUDIT)) {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
			o2.put("action", event.getAction());
			o2.put("message", event.getMessage());
			o2.put("role", event.getRole());
			o2.put("author", event.getAuthor());
			o2.put("source_ip", event.getSourceIp());
		} else if (event.getType().endsWith(Events.SOFFID_LOG)) {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
			o2.put("action", event.getAction());
			o2.put("source_ip", event.getSourceIp());
		} else {
			JSONObject subject = encodeSubject(r, event);
			o2.put("subject", subject);
		}
		o2.put("event_timestamp", event.getDate().getTime());
		return o2;
	}

	private void calculateSubject(SseEvent event, SseReceiver r, Account[] account, User[] user, ServletContext servletContext) throws Exception {
		if (event.getSubject() == null) {
			if (event.getUser() != null) {
				try {
					user[0] = new RemoteServiceLocator().getServerService().getUserInfo(event.getUser(), null);
				} catch (UnknownUserException uue) {
					user[0] = null;
				}
				if (user[0] == null)
					return;
				calculateUserSubject(event, r, account, user, servletContext);
			}
			else if (event.getAccountName() != null) {
				Account acc = account[0] = new RemoteServiceLocator().getAccountService().findAccount(event.getAccountName(), event.getAccountSystem());
				if (acc != null) {
					if (acc instanceof UserAccount) {
						user[0] = new RemoteServiceLocator().getServerService().getUserInfo(((UserAccount) acc).getUser(), null);
						if (user[0] != null)
						{
							calculateUserSubject(event, r, account, user, servletContext);
							return;
						}
					}
					calculateAccountSubject(event, r, account, servletContext);
				}
			}
		}
	}

	protected void calculateUserSubject(SseEvent event, SseReceiver r, Account[] account, User[] user,
			ServletContext servletContext) throws InternalErrorException, IOException, Exception {
		if (r.getSourceType() == SubjectSourceEnumeration.SYSTEM) {
			for (UserAccount a: new RemoteServiceLocator().getServerService().getUserAccounts(user[0].getId(), r.getSourceSystem())) {
				event.setSubject(a.getName());
				account[0] = a;
			}
		}
		else if (r.getSourceType() == SubjectSourceEnumeration.EXPRESSION) {
			Map<String,Object> map = new HashMap<>();
			map.put("user", user[0]);
			map.put("account", account[0]);
			map.put("sseEvent", event);
			String subject = (String) Evaluator.instance().evaluate("subject for "+r.getName(), 
					map, 
					r.getSourceExpression());
			event.setSubject(subject);
		}
		else if (r.getSourceType() == SubjectSourceEnumeration.OAUTH_ATTRIBUTE) {
			Map<String, Object> att;
			try {
				TokenInfo t = new TokenInfo();
				t.setAuthentication(System.currentTimeMillis());
				t.setAuthenticationMethod("P");
				t.setCreated(System.currentTimeMillis());
				t.setExpires(System.currentTimeMillis());
				Collection<UserAccount> l = new RemoteServiceLocator().getServerService().getUserAccounts(user[0].getId(), IdpConfig.getConfig().getSystem().getName());
				if (l != null && !l.isEmpty()) {
					if (account[0].getSystem().equals(IdpConfig.getConfig().getSystem().getName()))
						t.setUser(account[0].getName());
					else 
						t.setUser(l.iterator().next().getName());
					final OpenIdRequest request = new OpenIdRequest();
					t.setRequest(request);
					if (r.getServiceProvider() == null)
						request.setFederationMember(IdpConfig.getConfig().getFederationMember());
					else
						request.setFederationMember(IdpConfig.getConfig().getFederationService().findFederationMemberByPublicId(r.getServiceProvider()));
	
					att = new UserAttributesGenerator().generateAttributes(servletContext, t, true, false, false);
					event.setSubject((String) att.get(r.getSourceOAuth()));
				}
			} catch (AttributeResolutionException e) {
				log.warn("Error resolving attributes", e);
				return;
			} catch (AttributeFilteringException e) {
				log.warn("Error filtering attributes", e);
				return;
			} catch (InternalErrorException e) {
				log.warn("Error evaluating claims", e);
				return;
			} catch (Exception e) {
				log.warn("Error generating response", e);
				return;
			}
		}
	}

	protected void calculateAccountSubject(SseEvent event, SseReceiver r, Account[] account, 
			ServletContext servletContext) throws InternalErrorException, IOException, Exception {
		if (r.getSourceType() == SubjectSourceEnumeration.SYSTEM) {
			if (account[0].getSystem().equals(r.getSourceSystem())) {
				event.setSubject(account[0].getName());
			}
		}
		else if (r.getSourceType() == SubjectSourceEnumeration.EXPRESSION) {
			Map<String,Object> map = new HashMap<>();
			map.put("user", null);
			map.put("account", account[0]);
			map.put("sseEvent", event);
			String subject = (String) Evaluator.instance().evaluate("subject for "+r.getName(), 
					map, 
					r.getSourceExpression());
			event.setSubject(subject);
		}
		else if (r.getSourceType() == SubjectSourceEnumeration.OAUTH_ATTRIBUTE) {
			if (account[0].getSystem().equals(IdpConfig.getConfig().getSystem().getName())) {
				Map<String, Object> att;
				try {
					TokenInfo t = new TokenInfo();
					t.setAuthentication(System.currentTimeMillis());
					t.setAuthenticationMethod("P");
					t.setCreated(System.currentTimeMillis());
					t.setExpires(System.currentTimeMillis());
					t.setUser(account[0].getName());
					final OpenIdRequest request = new OpenIdRequest();
					t.setRequest(request);
					if (r.getServiceProvider() == null)
						request.setFederationMember(IdpConfig.getConfig().getFederationMember());
					else
						request.setFederationMember(IdpConfig.getConfig().getFederationService().findFederationMemberByPublicId(r.getServiceProvider()));
	
					att = new UserAttributesGenerator().generateAttributes(servletContext, t, true, false, false);
					event.setSubject((String) att.get(r.getSourceOAuth()));
				} catch (AttributeResolutionException e) {
					log.warn("Error resolving attributes", e);
					return;
				} catch (AttributeFilteringException e) {
					log.warn("Error filtering attributes", e);
					return;
				} catch (InternalErrorException e) {
					log.warn("Error evaluating claims", e);
					return;
				} catch (Exception e) {
					log.warn("Error generating response", e);
					return;
				}
			}
		}
	}

	protected JSONObject encodeSubject(SseReceiver r, SseEvent event) {
		JSONObject subject = new JSONObject();
		if (event.getSubject() == null)
			return null;
		if (r.getSubjectType() == SubjectFormatEnumeration.ISS_SUB) {
			subject.put("format", "iss_sub");
			subject.put("sub", event.getSubject());
			subject.put("iss", r.getIdentityProvider());
		}
		else if (r.getSubjectType() == SubjectFormatEnumeration.ACCOUNT) {
			subject.put("format", "account");
			subject.put("uri", event.getSubject());
		}
		else if (r.getSubjectType() == SubjectFormatEnumeration.DID)
		{
			subject.put("format", "did");
			subject.put("url", event.getSubject());
		}
		else if (r.getSubjectType() == SubjectFormatEnumeration.EMAIL) {
			subject.put("format", "email");
			subject.put("email", event.getSubject());
		}
		else if (r.getSubjectType() == SubjectFormatEnumeration.OPAQUE) {
			subject.put("format", "opaque");
			subject.put("id", event.getSubject());
		}
		else if (r.getSubjectType() == SubjectFormatEnumeration.PHONE_NUMBER) {
			subject.put("format", "phone_number");
			subject.put("phone_number", event.getSubject());
		}
		else if (r.getSubjectType() == SubjectFormatEnumeration.URI) {
			subject.put("format", "uri");
			subject.put("uri", event.getSubject());
		}
		return subject;
	}

	public boolean applies(SseReceiver receiver, SseEvent event, ServletContext servletContext) throws Exception {
		if (receiver.isSubscribeAll()) 
			return true;
		Account[] account = {null};
		User[] user = {null};
		if (event.getSubject() == null) {
			calculateSubject(event, receiver, account, user, servletContext);
		}
		if (event.getSubject() == null)
			return false;
		return ! new RemoteServiceLocator().getSharedSignalEventsService().findSubscriptions(receiver, event.getSubject()).isEmpty();
	}

}
