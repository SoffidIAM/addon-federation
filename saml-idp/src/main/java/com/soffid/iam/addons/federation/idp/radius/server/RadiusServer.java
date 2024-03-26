/**
 * $Id: RadiusServer.java,v 1.11 2008/04/24 05:22:50 wuttke Exp $
 * Created on 09.04.2005
 * @author Matthias Wuttke
 * @version $Revision: 1.11 $
 */
package com.soffid.iam.addons.federation.idp.radius.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.security.cert.X509Certificate;
import javax.servlet.ServletContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.soffid.iad.addons.federation.idp.tacacs.TacacsKeyManager;
import com.soffid.iam.addons.federation.common.FederationMember;
import com.soffid.iam.addons.federation.common.ServiceProviderType;
import com.soffid.iam.addons.federation.idp.radius.attribute.IntegerAttribute;
import com.soffid.iam.addons.federation.idp.radius.attribute.IpAttribute;
import com.soffid.iam.addons.federation.idp.radius.attribute.RadiusAttribute;
import com.soffid.iam.addons.federation.idp.radius.attribute.StringAttribute;
import com.soffid.iam.addons.federation.idp.radius.attribute.VendorSpecificAttribute;
import com.soffid.iam.addons.federation.idp.radius.packet.AccessRequest;
import com.soffid.iam.addons.federation.idp.radius.packet.AccountingRequest;
import com.soffid.iam.addons.federation.idp.radius.packet.RadiusPacket;
import com.soffid.iam.addons.federation.remote.RemoteServiceLocator;
import com.soffid.iam.addons.federation.service.FederationService;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.User;
import com.soffid.iam.service.OTPValidationService;
import com.soffid.iam.ssl.SeyconKeyStore;

import edu.internet2.middleware.shibboleth.common.attribute.filtering.AttributeFilteringException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.idp.openid.server.OpenIdRequest;
import es.caib.seycon.idp.openid.server.TokenInfo;
import es.caib.seycon.idp.openid.server.UserAttributesGenerator;
import es.caib.seycon.idp.server.Autenticator;
import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.server.AuthorizationHandler;
import es.caib.seycon.idp.ui.Messages;

/**
 * Implements a simple Radius server. This class must be subclassed to
 * provide an implementation for getSharedSecret() and getUserPassword().
 * If the server supports accounting, it must override
 * accountingRequestReceived().
 */
public class RadiusServer {
	Log log = LogFactory.getLog(getClass());
	private ServletContext servletContext;
	private SSLServerSocket secureSocket;
	private CertificateCache certificateCache;
	
	public FederationMember getServiceProvider(InetSocketAddress client, String nasIdentifier) throws InternalErrorException, IOException {
		final Collection<FederationMember> servers = new RemoteServiceLocator().getFederacioService().findFederationMemberByEntityGroupAndPublicIdAndTipus(null, null, "S");
		for (FederationMember sp: servers) {
			if (sp.getServiceProviderType() == ServiceProviderType.RADIUS &&
					(sp.getServerCertificate() == null || sp.getServerCertificate() == null)) {
				if (NetmaskMatch.matches(sp.getSourceIps(), client.getAddress()) ) {
					if (nasIdentifier == null || nasIdentifier.equals(sp.getPublicId()))
						return sp;
				}
			}
		}
		for (FederationMember sp: servers) {
			if (sp.getServiceProviderType() == ServiceProviderType.RADIUS &&
					(sp.getServerCertificate() == null || sp.getServerCertificate() == null)) {
				if (NetmaskMatch.matches(sp.getSourceIps(), client.getAddress())) {
					return sp;
				}
			}
		}
		return null;
	}
	
	public FederationMember getServiceProvider(InetSocketAddress client, String nasIdentifier, X509Certificate certs[]) throws InternalErrorException, IOException {
		if (certs != null && certs.length > 0) {
			return getCertificateCache().getFederationMember(certs[0]);
		}
		else
			return getServiceProvider(client, nasIdentifier);
	}


	/**
	 * Constructs an answer for an Access-Request packet. Either this
	 * method or isUserAuthenticated should be overriden.
	 * @param accessRequest Radius request packet
	 * @param client address of Radius client
	 * @return response packet or null if no packet shall be sent
	 * @exception RadiusException malformed request packet; if this
	 * exception is thrown, no answer will be sent
	 * @throws InternalErrorException 
	 * @throws IOException 
	 * @throws SignatureException 
	 * @throws NoSuchProviderException 
	 * @throws IllegalStateException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws FileNotFoundException 
	 * @throws InvalidKeyException 
	 * @throws UnrecoverableKeyException 
	 */
	public RadiusPacket accessRequestReceived(AccessRequest accessRequest, InetSocketAddress client, FederationMember member, boolean secure)
	throws RadiusException, UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		AuthenticationContext ctx;
		try {
			ctx = AuthenticationContext.fromRequest(accessRequest, client.getAddress(), member.getPublicId(), secure);
			
	    	log.info("Trying to login "+ctx.getUser());
	    	log.info("Authentication methods: "+ctx.getAllowedAuthenticationMethods());
		} catch (InternalErrorException e) {
			log.warn("Cannot authenticate user "+accessRequest.getUserName()+" for "+member.getPublicId());
			RadiusPacket answer = new RadiusPacket(RadiusPacket.ACCESS_REJECT, accessRequest.getPacketIdentifier());
			copyProxyState(accessRequest, answer);
			return answer;
		}

		boolean ok;
		Set<String> type = ctx.getNextFactor();
		if (type.contains("P"))
			ok = processPasswordAuth(ctx, accessRequest, client, member);
		else if (type.contains("O") || type.contains("M") || type.contains("S") || type.contains("I"))
			ok = processOtp (ctx, accessRequest, client, member);
		else {
			log.warn("Unable to authenticate using mechanism "+ctx.getAllowedAuthenticationMethods());
			ok = false;
		}
		if (ok) {
			if (ctx.isFinished()) {
				try {
					FederationService fs = new RemoteServiceLocator().getFederacioService();
			    	if (new AuthorizationHandler().checkAuthorization(ctx.getUser(), member,
			    			null, client.getAddress().toString())) {
	
				    	RadiusPacket answer = new RadiusPacket(RadiusPacket.ACCESS_ACCEPT, accessRequest.getPacketIdentifier());
						copyProxyState(accessRequest, answer);
							addCustomAttributes(answer, ctx.getUser(), member);
							return answer;
			    	} else {
			    		log.warn("User "+ctx.getUser()+" not authorized to login to "+member.getPublicId());
			    		return new RadiusPacket(RadiusPacket.ACCESS_REJECT, accessRequest.getPacketIdentifier());		    		
			    	}
				} catch (Exception e) {
					log.warn("Error generating radius response", e);
					return new RadiusPacket(RadiusPacket.ACCESS_REJECT, accessRequest.getPacketIdentifier());
				}
			}
			else {
            	OTPValidationService v = new com.soffid.iam.remote.RemoteServiceLocator().getOTPValidationService();
            	
            	Challenge ch = generateChallenge(ctx);
            	if (ch.getOtpHandler().length() == 0) {
        			log.warn("Unable to authenticate using mechanism "+ctx.getAllowedAuthenticationMethods());
        			ok = false;
            	}
            	else
            	{
		        	ch = v.selectToken(ch);
		        	ctx.setChallenge(ch);
		        	RadiusPacket answer = new RadiusPacket(RadiusPacket.ACCESS_CHALLENGE, accessRequest.getPacketIdentifier());
		        	copyProxyState(accessRequest, answer);
		        	answer.addAttribute(new IntegerAttribute(76, 0)); // Echo
		        	answer.addAttribute(new StringAttribute(24, ctx.getRadiusState())); // State
		        	if (ch.getCardNumber() == null)
		        	{
		        		log.warn("No OTP available for user "+ctx.getUser());
		        		ok = false;
		        	}
		        	else 
		        	{
		        		answer.addAttribute(new StringAttribute(18, ch.getCardNumber()+" "+ch.getCell()+": ")); // Replay message
		        		return answer;
		        	}
            	}
			}
		}
		
		RadiusPacket answer = new RadiusPacket(RadiusPacket.ACCESS_REJECT, accessRequest.getPacketIdentifier());
		copyProxyState(accessRequest, answer);
		return answer;
	}

	private Challenge generateChallenge(AuthenticationContext ctx) {
		Challenge ch = new Challenge();
		ch.setUser(ctx.getCurrentUser());
		StringBuffer otpType = new StringBuffer();
		if (ctx.getNextFactor().contains("O")) otpType.append("OTP ");
		if (ctx.getNextFactor().contains("M")) otpType.append("EMAIL ");
		if (ctx.getNextFactor().contains("I")) otpType.append("PIN ");
		if (ctx.getNextFactor().contains("S")) otpType.append("SMS ");
		ch.setOtpHandler(otpType.toString());
		return ch;
	}
	
	private void addCustomAttributes(RadiusPacket answer, String user, FederationMember member) throws AttributeResolutionException, AttributeFilteringException, InternalErrorException, IOException {
		Map<String, Object> attributes = generateAttributes(user, member);
		for (String att: attributes.keySet()) {
			Object value = attributes.get(att);
			try {
				if (value instanceof List) {
					for (Object o: (List) value)
						addAttribute(answer, att, o);
				}
				else
					addAttribute(answer, att, value);
			} catch (NumberFormatException e) {
				log.warn("Cannot parse attribute id "+att, e);
			}
		}
	}

	public Map<String, Object> generateAttributes(String user, FederationMember member)
			throws AttributeResolutionException, AttributeFilteringException, InternalErrorException, IOException {
		TokenInfo t = new TokenInfo();
		t.setAuthentication(System.currentTimeMillis());
		t.setAuthenticationMethod("P");
		t.setCreated(System.currentTimeMillis());
		t.setExpires(System.currentTimeMillis());
		t.setUser(user);
		final OpenIdRequest request = new OpenIdRequest();
		t.setRequest(request);
		request.setFederationMember(member);
		Map<String, Object> attributes = new UserAttributesGenerator().generateAttributes(servletContext, t, false, true, false);
		return attributes;
	}

	private void addAttribute(RadiusPacket answer, String att, Object value) {
		if (value != null)
			answer.addAttribute(createAttribute( att, value ) );
	}

	private RadiusAttribute createAttribute(String att, Object value) {
		if (att.contains(".")) {
			int i = att.indexOf(".");
			Integer vendor = Integer.decode(att.substring(0, i));
			String id = att.substring(i+1);
			final RadiusAttribute sub = createAttribute (id, value);
			sub.setVendorId(vendor.intValue());
			return sub;
		}
		else {
			Integer id = Integer.decode(att);
			if (value instanceof Integer) 
				return new IntegerAttribute(id, ((Integer) value).intValue());
			else if (value instanceof Integer) 
				return new IntegerAttribute(id, ((Long) value).intValue());
			else if (value instanceof InetAddress) 
				return new IpAttribute(id, ((InetAddress)value).getHostAddress());
			else
				return new StringAttribute(id, value.toString());
		}
	}

	private boolean processOtp(AuthenticationContext ctx, AccessRequest accessRequest, InetSocketAddress client,
			FederationMember member) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException {
    	OTPValidationService v = new com.soffid.iam.remote.RemoteServiceLocator().getOTPValidationService();
    	IdpConfig config = IdpConfig.getConfig();
    	
    	Challenge ch = ctx.getChallenge();
    	if (ch == null) {
    		ch = generateChallenge(ctx);
        	ch = v.selectToken(ch);
        	ctx.setChallenge(ch);
    	}
    	if (ch == null ||  ch.getCardNumber() == null)
    	{
    		log.warn("Unexpected condition. Token has not been issued");
    		return false;
    	}
    	else if (accessRequest.getUserPassword() == null) {
    		log.warn("Missing challenge response");
    		return false;
    	}
    	else if (v.validatePin(ch, accessRequest.getUserPassword())) {
    		Set<String> nf = ctx.getNextFactor();
    		if (nf.contains("I"))
    			ctx.authenticated(ctx.getUser(), "I", null); //$NON-NLS-1$
    		else if (nf.contains("S")) 
    			ctx.authenticated(ctx.getUser(), "S", null); //$NON-NLS-1$
    		else if (nf.contains("M")) 
    			ctx.authenticated(ctx.getUser(), "M", null); //$NON-NLS-1$
    		else if (nf.contains("O")) 
    			ctx.authenticated(ctx.getUser(), "O", null); //$NON-NLS-1$
    		return true;
        } else {
        	return false;
        }
	}

	private boolean processPasswordAuth(AuthenticationContext ctx, AccessRequest accessRequest,
			InetSocketAddress client, FederationMember member) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException, RadiusException {
		String plaintext = getUserPassword(accessRequest.getUserName());
		if (plaintext != null && accessRequest.verifyPassword(plaintext)) {
			ctx.authenticated(ctx.getUser(), "P", null); //$NON-NLS-1$
			return true;
		}
		else
			return false;
	}

	private String getUserPassword(String userName) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, IOException, InternalErrorException {
		String system = IdpConfig.getConfig().getSystem().getName();
		Password pass = new RemoteServiceLocator().getServerService().getAccountPassword(userName, system);
		if (pass == null)
			return null;
		else
			return pass.getPassword();
	}

	/**
	 * Constructs an answer for an Accounting-Request packet. This method
	 * should be overriden if accounting is supported.
	 * @param accountingRequest Radius request packet
	 * @param client address of Radius client
	 * @return response packet or null if no packet shall be sent
	 * @exception RadiusException malformed request packet; if this
	 * exception is thrown, no answer will be sent
	 */
	public RadiusPacket accountingRequestReceived(AccountingRequest accountingRequest, InetSocketAddress client) 
	throws RadiusException {
		RadiusPacket answer = new RadiusPacket(RadiusPacket.ACCOUNTING_RESPONSE, accountingRequest.getPacketIdentifier());
		copyProxyState(accountingRequest, answer);
		return answer;
	}
	
	/**
	 * Starts the Radius server.
	 * @param listenAuth open auth port?
	 * @param listenAcct open acct port?
	 */
	public void start(boolean listenAuth, boolean listenAcct) {
		if (listenAuth) {
			new Thread() {
				public void run() {
					setName("Radius Auth Listener");
					try {
						logger.info("starting RadiusAuthListener on port " + getAuthPort());
						listenAuth();
						logger.info("RadiusAuthListener is being terminated");
					} catch(Exception e) {
						e.printStackTrace();
						logger.fatal("auth thread stopped by exception", e);
					} finally {
						authSocket.close();
						logger.debug("auth socket closed");
					}
				}
			}.start();
		}
		
		if (listenAcct) {
			new Thread() {
				public void run() {
					setName("Radius Acct Listener");
					try {
						logger.info("starting RadiusAcctListener on port " + getAcctPort());
						listenAcct();
						logger.info("RadiusAcctListener is being terminated");
					} catch(Exception e) {
						e.printStackTrace();
						logger.fatal("acct thread stopped by exception", e);
					} finally {
						acctSocket.close();
						logger.debug("acct socket closed");
					}
				}
			}.start();
		}
		
		if (securePort != null) {
			new Thread() {
				public void run() {
					setName("Radius secure listener");
					try {
						listenSecure();
					} catch(Exception e) {
						e.printStackTrace();
						logger.fatal("acct thread stopped by exception", e);
					} finally {
						acctSocket.close();
						logger.debug("acct socket closed");
					}
				}
			}.start();
		}
	}
	
	/**
	 * Stops the server and closes the sockets.
	 */
	public void stop() {
		logger.info("stopping Radius server");
		closing = true;
		if (authSocket != null)
			authSocket.close();
		if (acctSocket != null)
			acctSocket.close();
	}
	
	/**
	 * Returns the auth port the server will listen on.
	 * @return auth port
	 */
	public int getAuthPort() {
		return authPort;
	}
	
	/**
	 * Sets the auth port the server will listen on.
	 * @param authPort auth port, 1-65535
	 */
	public void setAuthPort(int authPort) {
		if (authPort < 1 || authPort > 65535)
			throw new IllegalArgumentException("bad port number");
		this.authPort = authPort;
		this.authSocket = null;
	}
	
	/**
	 * Returns the socket timeout (ms).
	 * @return socket timeout
	 */
	public int getSocketTimeout() {
		return socketTimeout;
	}
	
	/**
	 * Sets the socket timeout.
	 * @param socketTimeout socket timeout, >0 ms
	 * @throws SocketException
	 */
	public void setSocketTimeout(int socketTimeout)
	throws SocketException {
		if (socketTimeout < 1)
			throw new IllegalArgumentException("socket tiemout must be positive");
		this.socketTimeout = socketTimeout;
		if (authSocket != null)
			authSocket.setSoTimeout(socketTimeout);
		if (acctSocket != null)
			acctSocket.setSoTimeout(socketTimeout);
	}
	
	/**
	 * Sets the acct port the server will listen on.
	 * @param acctPort acct port 1-65535
	 */
	public void setAcctPort(int acctPort) {
		if (acctPort < 1 || acctPort > 65535)
			throw new IllegalArgumentException("bad port number");
		this.acctPort = acctPort;
		this.acctSocket = null;
	}

	/**
	 * Returns the acct port the server will listen on.
	 * @return acct port
	 */
	public int getAcctPort() {
		return acctPort;
	}
	
	/**
	 * Returns the duplicate interval in ms.
	 * A packet is discarded as a duplicate if in the duplicate interval
	 * there was another packet with the same identifier originating from the
	 * same address.
	 * @return duplicate interval (ms)
	 */
	public long getDuplicateInterval() {
		return duplicateInterval;
	}

	/**
	 * Sets the duplicate interval in ms.
	 * A packet is discarded as a duplicate if in the duplicate interval
	 * there was another packet with the same identifier originating from the
	 * same address.
	 * @param duplicateInterval duplicate interval (ms), >0
	 */
	public void setDuplicateInterval(long duplicateInterval) {
		if (duplicateInterval <= 0)
			throw new IllegalArgumentException("duplicate interval must be positive");
		this.duplicateInterval = duplicateInterval;
	}
	
	/**
	 * Returns the IP address the server listens on.
	 * Returns null if listening on the wildcard address.
	 * @return listen address or null
	 */
	public InetAddress getListenAddress() {
		return listenAddress;
	}
	
	/**
	 * Sets the address the server listens on.
	 * Must be called before start().
	 * Defaults to null, meaning listen on every
	 * local address (wildcard address).
	 * @param listenAddress listen address or null
	 */
	public void setListenAddress(InetAddress listenAddress) {
		this.listenAddress = listenAddress;
	}
	
	/**
	 * Copies all Proxy-State attributes from the request
	 * packet to the response packet.
	 * @param request request packet
	 * @param answer response packet
	 */
	protected void copyProxyState(RadiusPacket request, RadiusPacket answer) {
		List proxyStateAttrs = request.getAttributes(33);
		for (Iterator i = proxyStateAttrs.iterator(); i.hasNext();) {
			RadiusAttribute proxyStateAttr = (RadiusAttribute)i.next();
			answer.addAttribute(proxyStateAttr);
		}		
	}
	
	/**
	 * Listens on the auth port (blocks the current thread).
	 * Returns when stop() is called.
	 * @throws SocketException
	 * @throws InterruptedException
	 * 
	 */
	protected void listenAuth()
	throws SocketException {
		listen(getAuthSocket());
	}
		
	/**
	 * Listens on the acct port (blocks the current thread).
	 * Returns when stop() is called.
	 * @throws SocketException
	 * @throws InterruptedException
	 */
	protected void listenAcct()
	throws SocketException {
		listen(getAcctSocket());
	}

	protected void listenSecure()
	throws IOException, KeyManagementException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
		SSLServerSocket socket = getSecureSocket();
		try {
			do {
				final SSLSocket s = (SSLSocket) socket.accept();
				new Thread( () -> {
					try {
						processSocket(s);
					} catch (IOException e) {
						log.warn("Error processing request", e);
					}
				} ).start();
			} while (true);
		} finally {
			socket.close();
		}
	}
	/**
	 * Listens on the passed socket, blocks until stop() is called.
	 * @param s socket to listen on
	 */
	protected void listen(DatagramSocket s) {
		DatagramPacket packetIn = new DatagramPacket(new byte[RadiusPacket.MAX_PACKET_LENGTH], RadiusPacket.MAX_PACKET_LENGTH);
		while (true) {
			try {
				// receive packet
				try {
					logger.trace("about to call socket.receive()");
					s.receive(packetIn);
					if (logger.isDebugEnabled())
						logger.debug("receive buffer size = " + s.getReceiveBufferSize());
				} catch (SocketException se) {
					if (closing) {
						// end thread
						logger.info("got closing signal - end listen thread");
						return;
					} else {
						// retry s.receive()
						logger.error("SocketException during s.receive() -> retry", se);
						continue;
					}
				}
								
				// check client
				InetSocketAddress localAddress = (InetSocketAddress)s.getLocalSocketAddress();
				InetSocketAddress remoteAddress = new InetSocketAddress(packetIn.getAddress(), packetIn.getPort());				
				// parse packet
				RadiusPacket request = makeRadiusPacket(packetIn);
				
				String nasIdentifier = request.getAttributeValue("NAS-Identifier");
				FederationMember member = getServiceProvider(remoteAddress, nasIdentifier);
				if (member == null) {
					if (logger.isInfoEnabled())
						logger.info("ignoring packet from unknown client " + remoteAddress + " received on local address " + localAddress);
					continue;
				}

				// decrypt attributes
				request.decodeRequestAttributes(member.getRadiusSecret().getPassword());
				request.checkRequestAuthenticator(member.getRadiusSecret().getPassword());

				if (logger.isInfoEnabled())
					logger.info("received packet from " + remoteAddress + " on local address " + localAddress + ": " + request);

				// handle packet
				logger.trace("about to call RadiusServer.handlePacket()");
				RadiusPacket response = handlePacket(localAddress, remoteAddress, request, member.getRadiusSecret().getPassword(), member, false);
				
				// send response
				if (response != null) {
					if (logger.isInfoEnabled())
						logger.info("send response: " + response);
					DatagramPacket packetOut = makeDatagramPacket(response, member.getRadiusSecret().getPassword(), remoteAddress.getAddress(), packetIn.getPort(), request);
					s.send(packetOut);
				} else
					logger.info("no response sent");						
			} catch (SocketTimeoutException ste) {
				// this is expected behaviour
				logger.trace("normal socket timeout");
			} catch (IOException ioe) {
				// error while reading/writing socket
				logger.error("communication error", ioe);
			} catch (RadiusException re) {
				// malformed packet
				logger.error("malformed Radius packet", re);
			} catch (Exception e) {
				logger.error("Error processing radius package", e);
			}
		}
	}

	protected void processSocket(SSLSocket s) throws IOException {
		InputStream in = s.getInputStream();
		OutputStream out = s.getOutputStream();
		while (! s.isClosed()) {
			try {
				// receive packet
				InetSocketAddress localAddress = (InetSocketAddress)s.getLocalSocketAddress();
				InetSocketAddress remoteAddress = new InetSocketAddress(s.getInetAddress(), s.getPort());				
				// parse packet
				RadiusPacket request = RadiusPacket.decodeRequestPacket(in);
				
				String nasIdentifier = request.getAttributeValue("NAS-Identifier");
				javax.security.cert.X509Certificate[] xcert = s.getSession().getPeerCertificateChain();
				X509Certificate[] cert = null;
				if (xcert.length > 0) {
					cert = new X509Certificate[xcert.length];
					for (int i = 0; i < xcert.length; i++)  {
						ByteArrayInputStream ba = new ByteArrayInputStream(xcert[i].getEncoded());
						cert[i] = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(ba);
					}
				}
				FederationMember member = getServiceProvider(remoteAddress, nasIdentifier, cert);
				if (member == null) {
					if (logger.isInfoEnabled())
						logger.info("ignoring packet from unknown client " + remoteAddress + " received on local address " + localAddress);
					continue;
				}

				// decrypt attributes
				request.decodeRequestAttributes(member.getRadiusSecret().getPassword());
				request.checkRequestAuthenticator(member.getRadiusSecret().getPassword());

				if (logger.isInfoEnabled())
					logger.info("received packet from " + remoteAddress + " on local address " + localAddress + ": " + request);

				// handle packet
				logger.trace("about to call RadiusServer.handlePacket()");
				RadiusPacket response = handlePacket(localAddress, remoteAddress, request, "radsec", member, xcert != null && xcert.length > 0);
				
				// send response
				if (response != null) {
					if (logger.isInfoEnabled())
						logger.info("send response: " + response);
					response.encodeResponsePacket(out, member.getRadiusSecret().getPassword(), request);
					out.flush();
				} else
					logger.info("no response sent");						
			} catch (SocketTimeoutException ste) {
				// this is expected behaviour
				logger.trace("normal socket timeout");
			} catch (SSLHandshakeException e) {
				log.warn("Connection not allowed from "+s.getInetAddress().toString()+": "+e.getMessage());
			} catch (IOException ioe) {
				// error while reading/writing socket
				logger.error("communication error", ioe);
			} catch (RadiusException re) {
				// malformed packet
				logger.error("malformed Radius packet", re);
			} catch (Exception e) {
				logger.error("Error processing radius package", e);
			}
		}
	}

	/**
	 * Handles the received Radius packet and constructs a response. 
	 * @param localAddress local address the packet was received on
	 * @param remoteAddress remote address the packet was sent by
	 * @param request the packet
	 * @return response packet or null for no response
	 * @throws RadiusException
	 * @throws InternalErrorException 
	 * @throws SignatureException 
	 * @throws NoSuchProviderException 
	 * @throws IllegalStateException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws InvalidKeyException 
	 * @throws UnrecoverableKeyException 
	 */
	protected RadiusPacket handlePacket(InetSocketAddress localAddress, InetSocketAddress remoteAddress, RadiusPacket request, String sharedSecret, FederationMember member,
			boolean secure) 
	throws RadiusException, IOException, UnrecoverableKeyException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException {
		RadiusPacket response = null;
		
		// check for duplicates
		if (!isPacketDuplicate(request, remoteAddress)) {
			if (localAddress.getPort() == getAuthPort()) {
				// handle packets on auth port
				if (request instanceof AccessRequest)
					response = accessRequestReceived((AccessRequest)request, remoteAddress, member, secure);
				else
					logger.error("unknown Radius packet type: " + request.getPacketType());
			} else if (localAddress.getPort() == getAcctPort()) {
				// handle packets on acct port
				if (request instanceof AccountingRequest)
					response = accountingRequestReceived((AccountingRequest)request, remoteAddress);
				else
					logger.error("unknown Radius packet type: " + request.getPacketType());
			} else {
				// ignore packet on unknown port
			}
		} else
			logger.info("ignore duplicate packet");

		return response;
	}

	/**
	 * Returns a socket bound to the auth port.
	 * @return socket
	 * @throws SocketException
	 */
	protected DatagramSocket getAuthSocket() 
	throws SocketException {
		if (authSocket == null) {
			if (getListenAddress() == null)
				authSocket = new DatagramSocket(getAuthPort());
			else
				authSocket = new DatagramSocket(getAuthPort(), getListenAddress());
			authSocket.setSoTimeout(getSocketTimeout());
		}
		return authSocket;
	}

	/**
	 * Returns a socket bound to the acct port.
	 * @return socket
	 * @throws SocketException
	 */
	protected DatagramSocket getAcctSocket() 
	throws SocketException {
		if (acctSocket == null) {
			if (getListenAddress() == null)
				acctSocket = new DatagramSocket(getAcctPort());
			else
				acctSocket = new DatagramSocket(getAcctPort(), getListenAddress());
			acctSocket.setSoTimeout(getSocketTimeout());
		}
		return acctSocket;
	}

	protected SSLServerSocket getSecureSocket() 
	throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, UnrecoverableKeyException {
		if (secureSocket == null) {
			SSLContext sslCtx = SSLContext.getInstance("TLS"); //$NON-NLS-1$
			
			KeyStore keyStore = SeyconKeyStore.loadKeyStore(SeyconKeyStore.getKeyStoreFile());
			List<String> keys = new LinkedList<String>();
			for (Enumeration<String> e = keyStore.aliases(); e.hasMoreElements();)
			{
				String alias = e.nextElement();
				if ( keyStore.isKeyEntry(alias) && ! alias.equalsIgnoreCase("idp"))
					keys.add(alias);
				if ( keyStore.isCertificateEntry(alias) && ! alias.equalsIgnoreCase(SeyconKeyStore.ROOT_CERT))
					keys.add(alias);
			}
			for (String key: keys)
				keyStore.deleteEntry(key);
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");        
			keyManagerFactory.init(keyStore, SeyconKeyStore.getKeyStorePassword().getPassword().toCharArray());
			
			sslCtx.init(new KeyManager[] { new TacacsKeyManager()}, 
					new TrustManager[] {new TrustRadiusServers(certificateCache)}, null);
			
			SSLServerSocketFactory sslFactory = sslCtx.getServerSocketFactory();
			secureSocket = (SSLServerSocket) sslFactory.createServerSocket(securePort);
		}
		return secureSocket;
	}

	/**
	 * Creates a Radius response datagram packet from a RadiusPacket to be send. 
	 * @param packet RadiusPacket
	 * @param secret shared secret to encode packet
	 * @param address where to send the packet
	 * @param port destination port
	 * @param request request packet
	 * @return new datagram packet
	 * @throws IOException
	 */
	protected DatagramPacket makeDatagramPacket(RadiusPacket packet, String secret, InetAddress address, int port,
			RadiusPacket request) 
	throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		packet.encodeResponsePacket(bos, secret, request);
		byte[] data = bos.toByteArray();
	
		DatagramPacket datagram = new DatagramPacket(data, data.length, address, port);
		return datagram;
	}
	
	/**
	 * Creates a RadiusPacket for a Radius request from a received
	 * datagram packet.
	 * @param packet received datagram
	 * @return RadiusPacket object
	 * @exception RadiusException malformed packet
	 * @exception IOException communication error (after getRetryCount()
	 * retries)
	 */
	protected RadiusPacket makeRadiusPacket(DatagramPacket packet) 
	throws IOException, RadiusException {
		ByteArrayInputStream in = new ByteArrayInputStream(packet.getData());
		return RadiusPacket.decodeRequestPacket(in);
	}
	
	/**
	 * Checks whether the passed packet is a duplicate.
	 * A packet is duplicate if another packet with the same identifier
	 * has been sent from the same host in the last time. 
	 * @param packet packet in question
	 * @param address client address
	 * @return true if it is duplicate
	 */
	protected boolean isPacketDuplicate(RadiusPacket packet, InetSocketAddress address) {
		long now = System.currentTimeMillis();
		long intervalStart = now - getDuplicateInterval();
		
		byte[] authenticator = packet.getAuthenticator();
		
		synchronized(receivedPackets) {
			for (Iterator i = receivedPackets.iterator(); i.hasNext();) {
				ReceivedPacket p = (ReceivedPacket)i.next();
				if (p.receiveTime < intervalStart) {
					// packet is older than duplicate interval
					i.remove();
				} else {
					if (p.address.equals(address) && p.packetIdentifier == packet.getPacketIdentifier()) {
						if (authenticator != null && p.authenticator != null) {
							// packet is duplicate if stored authenticator is equal
							// to the packet authenticator
							return Arrays.equals(p.authenticator, authenticator);
						} else {
							// should not happen, packet is duplicate
							return true;
						}
					}
				}
			}
		
			// add packet to receive list
			ReceivedPacket rp = new ReceivedPacket();
			rp.address = address;
			rp.packetIdentifier = packet.getPacketIdentifier();
			rp.receiveTime = now;
			rp.authenticator = authenticator;
			receivedPackets.add(rp);
		}

		return false;
	}

	private InetAddress listenAddress = null;
	private int authPort = 1812;
	private int acctPort = 1813;
	private DatagramSocket authSocket = null;
	private DatagramSocket acctSocket = null;
	private int socketTimeout = 3000;
	private List receivedPackets = new LinkedList();
	private long duplicateInterval = 30000; // 30 s
	private boolean closing = false;
	private Integer securePort;
	private static Log logger = LogFactory.getLog(RadiusServer.class);

	public ServletContext getServletContext() {
		return servletContext;
	}

	public void setServletContext(ServletContext servletContext) {
		this.servletContext = servletContext;
	}

	public void setSecurePort(Integer securePort) {
		this.securePort = securePort;
	}

	public CertificateCache getCertificateCache() {
		if (certificateCache == null)
			certificateCache = new CertificateCache();
		
		return certificateCache;
	}
	
}

/**
 * This internal class represents a packet that has been received by 
 * the server.
 */
class ReceivedPacket {
	
	/**
	 * The identifier of the packet.
	 */
	public int packetIdentifier;
	
	/**
	 * The time the packet was received.
	 */
	public long receiveTime;
	
	/**
	 * The address of the host who sent the packet.
	 */
	public InetSocketAddress address;
	
	/**
	 * Authenticator of the received packet.
	 */
	public byte[] authenticator;
	
}
