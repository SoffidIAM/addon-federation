package es.caib.seycon.idp.client;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import com.soffid.iam.api.Password;
import com.soffid.iam.api.PasswordValidation;
import com.soffid.iam.api.PolicyCheckResult;
import com.soffid.iam.remote.RemoteServiceLocator;
import com.soffid.iam.sync.service.LogonService;

import es.caib.seycon.idp.config.IdpConfig;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.exception.UnknownUserException;

public class PasswordManager {

    boolean mustChangePassword;

    private String getDispatcher() throws InternalErrorException
    {
    	IdpConfig cfg;
		try {
			cfg = IdpConfig.getConfig();
		} catch (Exception e) {
			throw new InternalErrorException("Error getting default dispatcher", e);
		}
    	return cfg.getSystem().getName();
    }
    /**
     * main
     * 
     * @param args
     * @throws IOException 
     * @throws FileNotFoundException 
     * @throws RemoteException 
     * @throws es.caib.seycon.ng.exception.InternalErrorException 
     * @throws es.caib.seycon.ng.exception.UnknownUserException 
     * @throws es.caib.seycon.ng.exception.InvalidPasswordException 
     */
    public boolean validate(String user, Password password) throws RemoteException, FileNotFoundException, IOException, es.caib.seycon.ng.exception.InternalErrorException, es.caib.seycon.ng.exception.InvalidPasswordException, es.caib.seycon.ng.exception.UnknownUserException {
    	LogonService logonService = new RemoteServiceLocator().getLogonService();
    	
        PasswordValidation pv = logonService.validatePassword(user, getDispatcher(), password.getPassword());
        switch (pv) {
        case PASSWORD_GOOD_EXPIRED:
            mustChangePassword = true;
        case PASSWORD_GOOD:
            return true;
        default:
            return false;
        }
    }
    
    public void changePassword(String user, Password passwordOld, Password passwordNew) throws RemoteException, FileNotFoundException, IOException, UnknownUserException, es.caib.seycon.ng.exception.InternalErrorException, es.caib.seycon.ng.exception.BadPasswordException, es.caib.seycon.ng.exception.InvalidPasswordException {
    	if (passwordOld == null)
    	{
    		changePassword(user, passwordNew);
    	} else {
	    	LogonService logonService = new RemoteServiceLocator().getLogonService();
	        logonService.changePassword(user,  getDispatcher(), passwordOld.getPassword(), passwordNew.getPassword());
	        mustChangePassword = false;
    	}
    }

    public void changePassword(String user, Password passwordNew) throws RemoteException, FileNotFoundException, IOException, UnknownUserException, es.caib.seycon.ng.exception.BadPasswordException, es.caib.seycon.ng.exception.InternalErrorException {
    	com.soffid.iam.sync.service.ServerService serverService = new com.soffid.iam.remote.RemoteServiceLocator().getServerService();
        serverService.changePasswordSync(user,  getDispatcher(), passwordNew, false);
        mustChangePassword = false;

    }
    
    public PolicyCheckResult checkPolicy (String userType, Password password) throws UnrecoverableKeyException, InvalidKeyException, FileNotFoundException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IllegalStateException, NoSuchProviderException, SignatureException, InternalErrorException, IOException
    {
    	return IdpConfig.getConfig().getFederationService().checkPolicy(userType, null, password);
    }

    public boolean mustChangePassword() {
        return mustChangePassword;
    }
}
