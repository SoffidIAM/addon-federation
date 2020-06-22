package com.soffid.iam.addons.federation.service.impl;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Map;

import org.opensaml.core.config.InitializationException;

import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.SamlValidationResults;
import com.soffid.iam.addons.federation.model.IdentityProviderEntity;
import com.soffid.iam.addons.federation.model.ServiceProviderEntity;
import com.soffid.iam.api.SamlRequest;
import com.soffid.iam.api.User;
import com.soffid.iam.model.SamlRequestEntity;

import es.caib.seycon.ng.exception.InternalErrorException;

public class OIDCServiceInternal extends AbstractFederationService {

	public OIDCServiceInternal() throws InitializationException {
		super();
	}

	public SamlValidationResults authenticateOidc(String serviceProvider, String protocol, Map<String, String> response,
			boolean autoProvision) throws InternalErrorException, IOException {
		try 
		{
			String state = response.get("state");
			SamlValidationResults r = new SamlValidationResults();
			OAuth2Consumer c = OAuth2Consumer.fromRequest(response);
			if (c == null)
			{
				r.setFailureReason("Received authentication response for unknown request "+state);
				log.info(r.getFailureReason());
				return r;
			}
				
			SamlRequestEntity requestEntity = samlRequestEntityDao.findByExternalId(state);
			log.info("authenticate() - requestEntity: "+requestEntity);
			if (requestEntity == null)
			{
				r.setFailureReason("Received authentication response for unknown request "+state);
				log.info(r.getFailureReason());
				return r;
			}
			if (requestEntity.isFinished() == true)
			{
				r.setFailureReason("Received authentication response for already served request "+state);
				log.info(r.getFailureReason());
				return r;
			}

			if (! c.verifyResponse(response))
				throw new InternalErrorException("Unable to get openid token");
	        
			User u = findAccountOwner (c.getPrincipal (), 
					c.getIdp().getPublicId(), 
					c.getAttributes(), 
					autoProvision);
			
			r.setAttributes(c.getAttributes());
			r.setIdentityProvider(c.getIdp().getPublicId());
			r.setUser(u);
			r.setValid(u != null);
			if (u == null)
				r.setFailureReason("Unknown user");
	
			StringBuffer sb = new StringBuffer();
			SecureRandom sr = new SecureRandom();
			for (int i = 0; i < 180; i++)
			{
				int random = sr.nextInt(64);
				if (random < 26)
					sb.append((char) ('A'+random));
				else if (random < 52)
					sb.append((char) ('a'+random-26));
				else if (random < 62)
					sb.append((char) ('0'+random-52));
				else if (random < 63)
					sb.append('+');
				else
					sb.append('/');
			}
			requestEntity.setKey(sb.toString());
			if (r.getUser() != null) {
				log.info("createAuthenticationRecord() - requestEntity.setUser("+r.getUser().getUserName()+")");
				requestEntity.setUser( r.getUser().getUserName() );
			}
			
			r.setSessionCookie(requestEntity.getExternalId()+":"+requestEntity.getKey());
			log.info("createAuthenticationRecord() - setSessionCookie(requestEntity.getExternalId()+\":\"+requestEntity.getKey())");
			requestEntity.setFinished(true);
			samlRequestEntityDao.update(requestEntity);

			return r;
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e ) {
			throw new InternalErrorException ("Error generating Openid-connect request", e);
		}
	}

	public SamlRequest generateOidcRequest(String serviceProvider, String identityProvider, String userName,
			long sessionSeconds) throws InternalErrorException {
		try {
			FederationMember sp;
			ServiceProviderEntity spe2 = findServiceProvider(serviceProvider);
			if (spe2 != null)
				sp = federationMemberEntityDao.toFederationMember(spe2);
			else {
				IdentityProviderEntity spe = findIdentityProvider(serviceProvider);
				if (spe != null)
					sp = federationMemberEntityDao.toFederationMember(spe);
				else
					throw new InternalErrorException("Unknown service provider "+serviceProvider);
			}

			IdentityProviderEntity idpe = findIdentityProvider(identityProvider);
			if (idpe == null)
				throw new InternalErrorException("Unknown identity provider "+identityProvider);
	
			FederationMember idp = federationMemberEntityDao.toFederationMember(idpe);
			
			OAuth2Consumer c ;
			if (idp.getIdpType() == IdentityProviderType.FACEBOOK)
				c = new FacebookConsumer(sp, idp);
			else if (idp.getIdpType() == IdentityProviderType.GOOGLE)
				c = new GoogleConsumer(sp, idp);
			else if (idp.getIdpType() == IdentityProviderType.LINKEDIN)
				c = new LinkedinConsumer(sp, idp);
			else if (idp.getIdpType() == IdentityProviderType.OPENID_CONNECT)
				c = new OpenidConnectConsumer(sp, idp);
			else
				throw new InternalErrorException("Unsupported identity provider "+ idp.getIdpType().toString());
	
			String newID = c.secretState;
			SamlRequest r = new SamlRequest();
			c.authRequest(r);
	
			// Record
			SamlRequestEntity reqEntity = samlRequestEntityDao.newSamlRequestEntity();
			reqEntity.setHostName(serviceProvider);
			reqEntity.setDate(new Date());
			reqEntity.setExpirationDate(new Date(System.currentTimeMillis()+sessionSeconds * 1000L));
			reqEntity.setExternalId(newID);
			reqEntity.setFinished(false);
			samlRequestEntityDao.create(reqEntity);
	
			return r;
		} catch (InternalErrorException e) {
			throw e;
		} catch (Exception e ) {
			throw new InternalErrorException ("Error generating Openid-connect request", e);
		}
	
	}


}
