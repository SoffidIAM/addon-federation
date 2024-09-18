package com.soffid.iam.addons.federation.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.iam.addons.federation.model.UserCredentialChallengeEntity;
import com.soffid.iam.addons.federation.model.UserCredentialEntity;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.api.User;
import com.soffid.iam.model.UserEntity;

public class PushAuthenticationServiceImpl extends PushAuthenticationServiceBase {
	Log log = LogFactory.getLog(getClass());
	SecureRandom random  = new SecureRandom();

	@Override
	protected boolean handleIsPushAuthenticationAccepted(UserCredentialChallenge challenge) throws Exception {
		UserCredentialChallengeEntity entity = getUserCredentialChallengeEntityDao().load(challenge.getId());
		return entity != null && entity.isSolved();
	}

	@Override
	protected Collection<UserCredentialChallenge> handleSendPushAuthentication(String user, String domain, boolean text) throws Exception {
		List<UserCredentialChallenge> currentChallenge = new LinkedList<>(); 
		UserEntity u = getUserEntityDao().findByUserName(user);
		if (u != null && u.getActive().equals("S")) {
			for (UserCredentialEntity cred: getUserCredentialEntityDao().findByUserId(u.getId())) {
				if (cred.getType() == UserCredentialType.PUSH) {
					getUserCredentialChallengeEntityDao().remove(cred.getChallenges());
					UserCredentialChallengeEntity ch = getUserCredentialChallengeEntityDao().newUserCredentialChallengeEntity();
					ch.setCreated(new Date());
					ch.setCredential(cred);
					ch.setSolved(false);
					if (cred.getVersion() != null && !cred.getVersion().isEmpty()) {
						String images[] = new String[4];
						int pos = random.nextInt(4);
						ch.setImage(generateRandom());
						images[pos] = ch.getImage();
						for (int i = 0; i < images.length; i++)
							if (images[i] == null) {
								boolean repeat;
								do {
									repeat = false;
									String r = generateRandom();
									for (int j = 0; j < images.length; j++ )
										if (r.equals(images[j]))
											repeat = true;
									images[i] = r;
								} while (repeat);
							}
						ch.setImage1(images[0]);
						ch.setImage2(images[1]);
						ch.setImage3(images[2]);
						ch.setImage4(images[3]);
						ch.setText(text);
					}
					getUserCredentialChallengeEntityDao().create(ch);
					currentChallenge.add( getUserCredentialChallengeEntityDao().toUserCredentialChallenge(ch) );
					if (cred.getVersion() != null && !cred.getVersion().isEmpty() && domain != null &&
							cred.getPushChannelToken() != null) {
						notify(cred, domain);
					}
				}
			}
		}
		return currentChallenge;
	}

	private void notify(UserCredentialEntity cred, String domain) throws IOException {
		final String token = cred.getPushChannelToken();
		new Thread( () -> {
			try {
				Thread.sleep(500);
				URL u = new URL("https://push-otp-notifier.tools.soffid.net/push-otp-tracker/notify");
				HttpURLConnection conn = (HttpURLConnection) u.openConnection();
				conn.setDoInput(true);
				conn.setDoOutput(true);
				conn.setRequestMethod("POST");
				conn.addRequestProperty("Content-Type", "application/x-www-form-urlencoded");
				OutputStream out = conn.getOutputStream();
				byte[] data = ("domain="+URLEncoder.encode(domain, "UTF-8")+"&token="+
						URLEncoder.encode(token, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
				out.write(data);
				out.close();
				InputStream in = conn.getInputStream();
				while (in.read() >= 0);
				in.close();
			} catch (Exception e) {
				// Ignore
			}
		}).start();
	}

	private String generateRandom() {
		int n = random.nextInt(100);
		return Integer.toString(n);
	}

	@Override
	protected Collection<UserCredentialChallenge> handleFindPushAuthentications(String credentialId) throws Exception {
		LinkedList l = new LinkedList<>();
		for (UserCredentialEntity cred: getUserCredentialEntityDao().findBySerialNumber(credentialId)) {
			if (cred.getType() == UserCredentialType.PUSH) {
				for (Iterator<UserCredentialChallengeEntity> it = cred.getChallenges().iterator(); it.hasNext(); ) {
					UserCredentialChallengeEntity ch = it.next();
					if (System.currentTimeMillis() - ch.getCreated().getTime() > 10*60*1000L) { // 10 minutes
						getUserCredentialChallengeEntityDao().remove(ch);
						it.remove();
					}
					else
					{
						l.add(getUserCredentialChallengeEntityDao().toUserCredentialChallenge(ch));
					}
				}
			}
		}
		return l;
	}

	@Override
	protected void handleResponsePushAuthentication(UserCredentialChallenge challenge, String response)
			throws Exception {
		UserCredentialChallengeEntity entity = getUserCredentialChallengeEntityDao().load(challenge.getId());
		if (entity != null) {
			UserCredentialEntity cred = entity.getCredential();
			if (cred.getType() == UserCredentialType.PUSH &&
					(cred.getExpirationDate() == null || cred.getExpirationDate().after(new Date()))) {
				if (response == null || response.trim().isEmpty()) {
					getUserCredentialChallengeEntityDao().remove(entity);
				} else {
					final HmacOneTimePasswordGenerator totp =
							new HmacOneTimePasswordGenerator(6, "HmacSHA1");
					
					byte buffer[] =  new Base32().decode(cred.getKey());
					final Key key = new SecretKeySpec(buffer, "RAW");
					long now = System.currentTimeMillis();
					now = now - now % 30000; 
					
					long lastUsed = cred.getLastUse() == null? 0: cred.getLastUse().getTime();
					// Check trail
					if (entity.getImage() != null) {
						if (! response.endsWith(entity.getImage())) {
							cred.setFails(cred.getFails() == null ? 1: cred.getFails() + 1);
							if (cred.getFails().intValue() > 10)
								cred.setExpirationDate(new Date());
							getUserCredentialEntityDao().update(cred);
							return;
						}
						response = response.substring(0, response.length() - entity.getImage().length());
					}
					// 5 minutes offset allowed
					int intValue;
					try {
						intValue = Integer.parseInt(response);
					} catch (NumberFormatException e) {
						return;
					}
					long seq = System.currentTimeMillis() / 30000L;
					lastUsed = lastUsed / 30000L;
					
					for (long i = seq - 10; i < seq + 10; i++)
					{
						if ( i > lastUsed && intValue == totp.generateOneTimePassword(key, i))
						{
							cred.setLastUse( new Date());
							cred.setFails(0);
							getUserCredentialEntityDao().update(cred);
							entity.setSolved(true);
							getUserCredentialChallengeEntityDao().update(entity);
							return;
						}
					}
					cred.setFails(cred.getFails() == null ? 1: cred.getFails() + 1);
					if (cred.getFails().intValue() > 10)
						cred.setExpirationDate(new Date());
					getUserCredentialEntityDao().update(cred);
					
				}
			}
		}
	}

	@Override
	protected void handleUpdatePushAuthenticationToken(String credentialId, String pushChannelToken,
			String operatingSystem, String model, String version) throws Exception {
		for (UserCredentialEntity entity: getUserCredentialEntityDao().findBySerialNumber(credentialId)) {
			if (entity.getType() == UserCredentialType.PUSH) {
				entity.setPushChannelToken(pushChannelToken);
				entity.setOperatingSystem(operatingSystem);
				entity.setModel(model);
				entity.setVersion(version);
				if (model != null && ! model.trim().isEmpty())
					entity.setDescription(model);
				getUserCredentialEntityDao().update(entity);
			}
		}
	}

}
