package com.soffid.iad.addons.federation.idp.tacacs;

import java.io.IOException;
import java.net.Socket;

import com.soffid.iam.addons.federation.common.FederationMember;

public class TacacsServer extends TacacsReader {
	protected TacacsServer(Socket socket, String key, FederationMember sp) throws IOException {
		super(socket, key, sp);
	}
}
