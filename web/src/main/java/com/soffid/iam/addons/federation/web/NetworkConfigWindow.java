package com.soffid.iam.addons.federation.web;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import org.zkoss.zk.ui.Component;
import org.zkoss.zk.ui.UiException;
import org.zkoss.zk.ui.event.Event;
import org.zkoss.zk.ui.ext.AfterCompose;
import org.zkoss.zul.Window;

import com.soffid.iam.addons.federation.common.IdpNetworkEndpointType;
import com.soffid.iam.web.component.CustomField3;
import com.soffid.iam.web.component.InputField3;

public class NetworkConfigWindow extends Window implements AfterCompose {
	private CustomField3 excludedProtocols;
	private CustomField3 certificateHeader;
	private CustomField3 proxyProtocol;
	private CustomField3 type;
	private CustomField3 port;
	private CustomField3 proxyInternalAddress;
	private CustomField3 proxyPort;
	private CustomField3 proxy;
	private List<String> originalTypes;
	private CustomField3 wantsCertificate;

	@Override
	public void afterCompose() {
		proxy = (CustomField3) getFellow("proxy");
		proxyPort = (CustomField3) getFellow("proxyPort");
		proxyInternalAddress = (CustomField3) getFellow("proxyInternalAddress");
		port = (CustomField3) getFellow("port");
		type = (CustomField3)  getFellow("type");
		proxyProtocol = (CustomField3)  getFellow("proxyProtocol");
		certificateHeader = (CustomField3)  getFellow("certificateHeader");
		excludedProtocols = (CustomField3)  getFellow("excludedProtocols");
		wantsCertificate = (CustomField3) getFellow("wantsCertificate");
		proxy.addEventListener("onChange", ev -> {
			showProxyPort();
			showProxyInternalAddress();
			showProxyProtocol();
			showCertificateHeader();
			changeTypeOptions();
			showCertificateHeader();
		});
		type.addEventListener("onChange", ev-> {
			showExcludedProtocol();
		});
		wantsCertificate.addEventListener("onChange", ev -> {
			showCertificateHeader();
		});
		originalTypes = type.getValues();
	}

	private void changeTypeOptions() {
		if (proxy.getValue().equals(Boolean.TRUE)) 
			type.setValues(originalTypes);
		else {
			LinkedList<String> l = new LinkedList<String>(originalTypes);
			for (Iterator<String> it = l.iterator(); it.hasNext();) {
				if (it.next().startsWith("PLAIN"))
					it.remove();
			}
			type.setValues(l);
		}
		try {
			type.updateMetadata();
		} catch (Exception e) {
			throw new UiException(e);
		}
	}

	private void showExcludedProtocol() {
		final Object value = type.getValue();
		IdpNetworkEndpointType t = (IdpNetworkEndpointType) (value instanceof IdpNetworkEndpointType ? value: null);
		excludedProtocols.setVisible(t == IdpNetworkEndpointType.TLSV_1_2 ||
				t == IdpNetworkEndpointType.TLSV_1_3);
	}

	private void showProxyProtocol() {
		proxyProtocol.setVisible(Boolean.TRUE.equals(proxy.getValue()));
	}

	private void showCertificateHeader() {
		certificateHeader.setVisible(Boolean.TRUE.equals(proxy.getValue()) &&
				Boolean.TRUE.equals(wantsCertificate.getValue()));
	}

	private void showProxyInternalAddress() {
		proxyInternalAddress.setVisible(Boolean.TRUE.equals(proxy.getValue()));
	}

	private void showProxyPort() {
		proxyPort.setVisible(Boolean.TRUE.equals(proxy.getValue()));
	}

	@Override
	public void doHighlighted() {
		super.doHighlighted();
		showProxyPort();
		showProxyInternalAddress();
		showProxyProtocol();
		showCertificateHeader();
		changeTypeOptions();
		showExcludedProtocol();
	}
	
	public void apply (Event ev) {
		Component c = getFellow("form");
		for (Object o: c.getChildren()) {
			if (o instanceof InputField3) {
				if ( ((InputField3) o).isVisible() && ! ((InputField3)o).attributeValidateAll())
					return;
			}
		}
		IdentityProvider idpw = (IdentityProvider) getParent();
		idpw.getDataSource().sendEvent( new es.caib.zkib.events.XPathRerunEvent(
				idpw.getDataSource(), idpw.getXPath()+"federationMember/networkConfig"));
		setVisible(false);
	}

}
