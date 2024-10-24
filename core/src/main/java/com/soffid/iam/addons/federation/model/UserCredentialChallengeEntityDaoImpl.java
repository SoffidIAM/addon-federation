package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.api.UserCredentialChallenge;

public class UserCredentialChallengeEntityDaoImpl extends UserCredentialChallengeEntityDaoBase {

	@Override
	public void toUserCredentialChallenge(UserCredentialChallengeEntity source, UserCredentialChallenge target) {
		super.toUserCredentialChallenge(source, target);
		if (source.getImage1() != null) {
			target.setIdentifiers(new int[4]);
			target.setImages(new String[4]);
			updateIdentifiers(target, 0, source.getImage1());
			updateIdentifiers(target, 1, source.getImage2());
			updateIdentifiers(target, 2, source.getImage3());
			updateIdentifiers(target, 3, source.getImage4());
			if (source.isText())
				target.setImageUrl(source.getImage());
			else
				target.setImageUrl(generateUrl(source.isText(), source.getImage()));
		}
		target.setDeviceVersion(source.getCredential().getVersion());
	}

	private void updateIdentifiers(UserCredentialChallenge target, int i, String image) {
		if (image != null) {
			final int num = Integer.parseInt(image);
			target.getIdentifiers()[i] = num;
			target.getImages()[i] = generateUrl(target.isText(), image);			
		}
	}

	protected String generateUrl(boolean text, final String num) {
		return text? 
				"https://download.soffid.com/doc/push-images/numbers/"+num+".jpg" :
				"https://download.soffid.com/doc/push-images/birds/"+num+".jpg";
	}

}
