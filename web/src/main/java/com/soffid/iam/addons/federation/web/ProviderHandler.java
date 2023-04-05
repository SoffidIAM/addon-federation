package com.soffid.iam.addons.federation.web;

import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.zkoss.util.resource.Labels;
import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.Executions;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zul.Window;

import com.soffid.iam.addons.federation.common.EntityGroup;
import com.soffid.iam.addons.federation.common.EntityGroupMember;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.IdentityProviderType;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.web.component.FrameHandler;
import com.soffid.iam.web.component.Menu2item;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.zkib.component.DataTree2;
import es.caib.zkib.datamodel.DataModelCollection;
import es.caib.zkib.datamodel.DataNode;
import es.caib.zkib.datasource.CommitException;
import es.caib.zkib.datasource.DataSource;
import es.caib.zkib.datasource.XPathUtils;
import es.caib.zkib.zkiblaf.Missatgebox;

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

	@Override
	public void afterCompose() {
		super.afterCompose();
		HttpServletRequest req = (HttpServletRequest) Executions.getCurrent().getNativeRequest();
		final String publicId = req.getParameter("filter");
		if (publicId != null)
		{
			DataTree2 tree = (DataTree2) getListbox();
			tree.setFilters(new String[] {publicId});	
			DataNode root = (DataNode) getModel().getJXPathContext().getValue("/");
			if (find(publicId, root, new int[0])) {
				showDetails();
				if ("adaptive".equals(req.getParameter("wizard"))) {
					Component identityProvider = getFellow("identity_provider");
					Window adaptiveAuthentication = (Window) identityProvider.getFellow("adaptiveAuthentication");
					adaptiveAuthentication.doHighlighted();
				}
			}
		}
	}

	private boolean find(String publicId, DataNode root, int pos[]) {
		Object o = root.getInstance();
		if (o instanceof EntityGroupMember) {
			EntityGroupMember egm = (EntityGroupMember) o;
			if (egm.getFederationMember() != null && publicId.equals(egm.getFederationMember().getPublicId())) {
				DataTree2 dt = (DataTree2) getListbox();
				dt.setSelectedIndex(pos);
				return true;
			}
		}
		DataModelCollection coll = root.getListModel("entitygroupmember");
		int[] newpos = Arrays.copyOf(pos, pos.length+1);
		for (int i = 0; i < coll.getSize(); i++) {
			DataNode dn = (DataNode) coll.getDataModel(i);
			if (!dn.isDeleted()) {
				newpos[pos.length] = i;
				if (find(publicId, dn, newpos))
					return true;
			}
		}
		return false;
	}

	public void confirmApply (Event e) throws CommitException {
		if (getModel() == null || ! getModel().isCommitPending()) {
			hideDetails();
		} else {
			Missatgebox.confirmaYES_NO(Labels.getLabel("aplica_usuarisRolllista.zul.Confirm"), (event) -> {
				if (event.getName().equals("onYes")) {
					apply(e);
				}
			});
		}
	}
}
