package com.soffid.iam.addons.federation.model;

import java.util.Date;
import java.util.List;

import com.soffid.iam.addons.federation.api.SseSubscription;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.DaoFinder;
import com.soffid.mda.annotation.DaoOperation;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_SSESUB")
@Depends({SseSubscription.class})
public class SseSubscriptionEntity {
	@Identifier @Column(name="SSS_ID")
	Long id;
	
	@Column(name="SSS_REC_ID", reverseAttribute = "subjects")
	SseReceiverEntity receiver;
	
	@Nullable
	@Column(name="SSS_USER", length = 256)
	String subject;
	
	@Column(name="SSS_DATE")
	Date date;
	
	@DaoFinder("select e "
			+ "from com.soffid.iam.addons.federation.model.SseSubscriptionEntity as e "
			+ "where e.receiver.name = :receiver "
			+ "order by e.id asc")
	List<SseSubscriptionEntity> findByReceiver(String receiver) { return null; }

	@DaoFinder("select e "
			+ "from com.soffid.iam.addons.federation.model.SseSubscriptionEntity as e "
			+ "where e.receiver.name = :receiver and e.subject=:subject "
			+ "order by e.id asc")
	List<SseSubscriptionEntity> findByReceiverAndUserName(String receiver, 
			String subject) { return null; }
	
	@DaoOperation
	void removeByReceiver(String receiver) {}
}

