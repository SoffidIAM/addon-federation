package com.soffid.iam.addons.federation.idp.radius.server;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedList;

public class NetmaskMatch {
	public NetmaskMatch(byte[] address, int bits) {
		super();
		this.address = address;
		this.bits = bits;
	}
	static byte pattern[] = new byte [] { 0, (byte) 0x80, (byte) 0xc0, (byte) 0xe0, (byte) 0xf0, (byte) 0xf8, (byte) 0xfc, (byte) 0xfe, (byte) 0xff} ;
	byte address[];
	int bits;
	public boolean match (byte[] addr2) {
		if (addr2.length  != address.length)
			return false;
		for (int pos = 0, i = 0; pos < addr2.length && i < bits; i += 8, pos ++) {
			if ( bits - i >= 8 ) {
				if (addr2[pos] != address[pos])
					return false;
			}
			else
			{
				byte p = pattern [bits-i];
				if ( (addr2[pos] & p) != (address[pos] & p))
					return false;
			}
		}
		return true;
	}

	public static boolean matches (String masks, InetAddress inetAddress) throws UnknownHostException {
		if (inetAddress == null)
			return false;
		byte[] bytes = inetAddress.getAddress();
		for (NetmaskMatch match: parseTrustedIps(masks)) {
			if (match.match(bytes))
				return true;
		}
		return false;
	}
	
	public static LinkedList<NetmaskMatch> parseTrustedIps(String s) throws UnknownHostException {
		LinkedList<NetmaskMatch> matches = new LinkedList<>();
		if (s != null) {
			for (String part: s.split("\\s*,\\s*")) {
				if (part.contains("*")) {
					part = part.substring(0, part.indexOf("*"));
					int dots = 0;
					int pos = 0;
					do {
						int i = part.indexOf(".", pos);
						if (i < 0) break;
						dots ++;
						pos = i+1;
					} while(true);
					if (dots == 0)
						part = part + "0.0.0.0/0";
					else if (dots == 1)
						part = part + "0.0.0/8";
					else if (dots == 2)
						part = part + "0.0/16";
					else
						part = part + "0/24";
				}
				int slash = part.indexOf("/");
				if (slash < 0) {
					byte[] addr = InetAddress.getByName(part).getAddress();
					matches.add(new NetmaskMatch(addr, addr.length * 8));
				} else {
					byte[] addr = InetAddress.getByName(part.substring(0, slash)).getAddress();
					int bits = Integer.parseInt(part.substring(slash+1));
					matches.add(new NetmaskMatch(addr, bits));
				}
			}
		}
		return matches;
	}

}
