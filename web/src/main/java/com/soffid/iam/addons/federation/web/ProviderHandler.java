package com.soffid.iam.addons.federation.web;

import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.event.Event;

import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.web.component.FrameHandler;
import com.soffid.iam.web.component.Menu2item;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.component.DataTree2;
import es.caib.zkib.datamodel.DataNode;
import es.caib.zkib.datasource.DataSource;
import es.caib.zkib.datasource.XPathUtils;

public class ProviderHandler extends FrameHandler {

	public ProviderHandler() throws InternalErrorException {
		super();
	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
	public void showDetails() {
		super.showDetails();
	}

	@Override
	public void onChangeForm(Event ev) throws Exception {
		super.onChangeForm(ev);
		String type = null;
		try {
			type = (String) XPathUtils.eval(getListbox(), "type");
		} catch (Exception e) {}
		Component item = getFellow("deleteMenuOption");
		item.setVisible("SP".equals(type) ||
				"EG".equals(type) ||
				"VIP".equals(type) ||
				"IDP".equals(type));
		getFellow("provider_root").setVisible("ARREL".equals(type));
		getFellow("entity_group").setVisible("EG".equals(type));
		getFellow("service_provider").setVisible("SP".equals(type));
		getFellow("identity_provider").setVisible("VIP".equals(type) || "IDP".equals(type));
		getFellow("service_providers").setVisible("SP_ROOT".equals(type));
		getFellow("identity_providers").setVisible("IDP_ROOT".equals(type));
	}

	public void addNewEntityGroup() {
		EntityGroupMember current = (EntityGroupMember) XPathUtils.eval(getListbox(), "instance");
		EntityGroupMember egm = new EntityGroupMember();
		egm.setType("EG");
		EntityGroup eg = new EntityGroup();
		egm.setEntityGroup(eg);
		
		DataTree2 tree = (DataTree2) getListbox();
		tree.addNew("/entitygroupmember", egm);
		showDetails();
	}

	public void addChild(Event event) {
		EntityGroupMember current = (EntityGroupMember) XPathUtils.eval(getListbox(), "instance");
		if (current.getType().equals("ARREL"))
			addNewEntityGroup();
		else if (current.getType().equals("IDP_ROOT"))
			addNewIdentityProvider();
		else if (current.getType().equals("SP_ROOT"))
			addNewServiceProvider();
		else if (current.getType().equals("IDP"))
			addNewVirtualIdentityProvider();
	}

	public void addNewIdentityProvider() {
		DataNode node =  (DataNode) XPathUtils.eval(getListbox(), ".");
		EntityGroupMember parent = (EntityGroupMember) ((DataNode)node.getParent()).getInstance();
		EntityGroupMember current = (EntityGroupMember) XPathUtils.eval(getListbox(), "instance");
		EntityGroupMember egm = new EntityGroupMember();
		egm.setType("IDP");
		EntityGroup eg = new EntityGroup();
		egm.setEntityGroup(parent.getEntityGroup());
		FederationMember fm = new FederationMember();
		fm.setIdpType(IdentityProviderType.SAML);
		fm.setClasse("I");
		fm.setEntityGroup(parent.getEntityGroup());
		egm.setFederationMember(fm);
		
		DataTree2 tree = (DataTree2) getListbox();
		tree.addNew("/entitygroupmember", egm);
		showDetails();		
	}

	public void addNewVirtualIdentityProvider() {
		DataNode node =  (DataNode) XPathUtils.eval(getListbox(), ".");
		EntityGroupMember parent = (EntityGroupMember) ((DataNode)node.getParent()).getInstance();
		EntityGroupMember current = (EntityGroupMember) XPathUtils.eval(getListbox(), "instance");
		EntityGroupMember egm = new EntityGroupMember();
		egm.setType("VIP");
		EntityGroup eg = new EntityGroup();
		egm.setEntityGroup(parent.getEntityGroup());
		FederationMember fm = new FederationMember();
		fm.setIdpType(IdentityProviderType.SOFFID);
		fm.setClasse("V");
		fm.setEntityGroup(parent.getEntityGroup());
		fm.setDefaultIdentityProvider(current.getFederationMember());
		egm.setFederationMember(fm);
		
		DataTree2 tree = (DataTree2) getListbox();
		tree.addNew("/entitygroupmember", egm);
		showDetails();		
	}

	public void addNewServiceProvider() {
		DataNode node =  (DataNode) XPathUtils.eval(getListbox(), ".");
		EntityGroupMember parent = (EntityGroupMember) ((DataNode)node.getParent()).getInstance();
		EntityGroupMember current = (EntityGroupMember) XPathUtils.eval(getListbox(), "instance");
		EntityGroupMember egm = new EntityGroupMember();
		egm.setType("SP");
		EntityGroup eg = new EntityGroup();
		egm.setEntityGroup(parent.getEntityGroup());
		FederationMember fm = new FederationMember();
		fm.setServiceProviderType(ServiceProviderType.SAML);
		fm.setClasse("S");
		egm.setFederationMember(fm);
		fm.setEntityGroup(parent.getEntityGroup());
		DataTree2 tree = (DataTree2) getListbox();
		tree.addNew("/entitygroupmember", egm);
		showDetails();		
	}
}
