package es.caib.seycon.idp.config;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.caib.seycon.ng.comu.Password;

public class PasswordCallbackHandler implements CallbackHandler {

    private Password password;

    public PasswordCallbackHandler(Password p) {
        this.password = p;
    }

    public void handle(Callback[] callbacks) throws IOException,
            UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++)
        {
              if (callbacks[i] instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback)callbacks[i];
                pc.setPassword(password.getPassword().toCharArray());
              } else {
                throw new UnsupportedCallbackException
                  (callbacks[i], "Unrecognized Callback");
              }
        }

    }

}
