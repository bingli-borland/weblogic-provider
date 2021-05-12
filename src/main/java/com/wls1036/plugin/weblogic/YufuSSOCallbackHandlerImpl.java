package com.wls1036.plugin.weblogic;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

class YufuSSOCallbackHandlerImpl implements CallbackHandler {
    private String userName;

    YufuSSOCallbackHandlerImpl(String user) {
        userName = user;
    }

    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            Callback callback = callbacks[i];
            if (!(callback instanceof NameCallback)) {
                throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
            }
            NameCallback nameCallback = (NameCallback) callback;
            nameCallback.setName(userName);
        }
    }
}
