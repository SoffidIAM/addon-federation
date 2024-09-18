package com.soffid.iam.addons.federation.model;

import java.util.Date;

import com.soffid.iam.addons.federation.api.UserCredentialChallenge;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_USCRCH")
@Depends({UserCredentialChallenge.class})
public class UserCredentialChallengeEntity {
	@Column(name = "UCC_ID")
	@Nullable @Identifier Long id;
	
	@Column(name = "UCC_UCR_ID", reverseAttribute = "challenges")
	UserCredentialEntity credential;
	
	@Column(name = "UCR_CREATED")
	Date created;
	
	@Nullable @Column(name = "UCR_IMAGE")
	String image;
	
	@Nullable @Column(name = "UCR_IMAGE1")
	String image1;

	@Nullable @Column(name = "UCR_IMAGE2")
	String image2;

	@Nullable @Column(name = "UCR_IMAGE3")
	String image3;

	@Nullable @Column(name = "UCR_IMAGE4")
	String image4;

	@Column(name="UCR_TEXT")
	boolean text;
	
	@Column(name = "UCR_SOLVED", defaultValue = "false")
	boolean solved;
}
