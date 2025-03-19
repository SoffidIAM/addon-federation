package es.caib.seycon.idp.ui;

import java.io.IOException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.soffid.iam.addons.otp.common.OtpConfig;
import com.soffid.iam.addons.otp.common.OtpDevice;
import com.soffid.iam.addons.otp.common.OtpDeviceType;
import com.soffid.iam.addons.otp.common.OtpStatus;
import com.soffid.iam.addons.otp.service.OtpService;
import com.soffid.iam.api.Challenge;
import com.soffid.iam.federation.idp.RemoteServiceLocator;

import es.caib.seycon.idp.server.AuthenticationContext;
import es.caib.seycon.idp.textformatter.TextFormatException;
import es.caib.seycon.ng.exception.InternalErrorException;

public class OTPGenerator {
	public boolean generateOtp(HttpServletRequest req, HttpServletResponse resp, HtmlGenerator g) throws TextFormatException, IOException, InternalErrorException {
		AuthenticationContext ctx = AuthenticationContext.fromRequest(req);
		
		String user = ctx.getCurrentUser().getUserName();
		
		OtpService svc = (OtpService) new RemoteServiceLocator().getRemoteService(OtpService.REMOTE_PATH);
		for (OtpDevice current: svc.findUserDevices(user)) {
			if (current.getStatus() == OtpStatus.VALIDATED ||
					current.getStatus() == OtpStatus.LOCKED) {
				return false;
			}
  		}
		
		OtpConfig cfg = svc.getConfiguration();
		
		OtpDevice currentDevice = ctx.getOtpDeviceToRegister();
		if (currentDevice == null) {
			currentDevice = new OtpDevice();
			if (cfg.isAllowTotp()) {
				currentDevice.setType(OtpDeviceType.TOTP);
				currentDevice.setCreated(new Date());
				currentDevice.setStatus(OtpStatus.CREATED);
				currentDevice = svc.registerDevice2(user, currentDevice);
				ctx.setOtpDeviceToRegister(currentDevice);
			}
			else if (cfg.isAllowHotp()) {
				currentDevice.setType(OtpDeviceType.HOTP);
				currentDevice.setCreated(new Date());
				currentDevice.setStatus(OtpStatus.CREATED);
				currentDevice = svc.registerDevice2(user, currentDevice);
				ctx.setOtpDeviceToRegister(currentDevice);
			}
			else
				return false;
		}
		g.addArgument("image", currentDevice.getPngImage());
		Challenge ch = svc.generateChallenge(currentDevice);
		g.addArgument("otpToken",  ch.getCardNumber()+" "+ch.getCell()); //$NON-NLS-1$ //$NON-NLS-2$
		g.addArgument("createOtpUrl", RegisterOtpAction.URI);
		ctx.setOtpDeviceChallenge(ch);
		g.generate(resp, "registerOtp.html"); //$NON-NLS-1$
		return true;
	}


}
