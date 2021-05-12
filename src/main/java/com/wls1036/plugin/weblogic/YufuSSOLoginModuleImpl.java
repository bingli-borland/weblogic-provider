package com.wls1036.plugin.weblogic;

import java.io.IOException;
import java.util.Map;
import java.util.Vector;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import weblogic.security.principal.WLSGroupImpl;
import weblogic.security.principal.WLSUserImpl;


final public class YufuSSOLoginModuleImpl implements LoginModule {
    private Subject subject;
    private CallbackHandler callbackHandler;


    private boolean loginSucceeded;
    private boolean principalsInSubject;
    private Vector principalsForSubject = new Vector();

    public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
        System.out.println("YufuSSOLoginModuleImpl.initialize");
        this.subject = subject;
        this.callbackHandler = callbackHandler;
    }

    /**
     * 登录逻辑
     *
     * @return
     * @throws LoginException
     */
    public boolean login() throws LoginException {
        System.out.println("插件校验登录");
        Callback[] callbacks = getCallbacks();
        String userName = getUserName(callbacks);
        loginSucceeded = true;
        principalsForSubject.add(new WLSUserImpl(userName));
        addGroupsForSubject(userName);
        return loginSucceeded;
    }

    /**
     * 确认登录成功
     *
     * @return
     * @throws LoginException
     */
    public boolean commit() throws LoginException {
        if (loginSucceeded) {
            subject.getPrincipals().addAll(principalsForSubject);
            principalsInSubject = true;
            return true;
        } else {
            return false;
        }
    }

    public boolean abort() throws LoginException {
        if (principalsInSubject) {
            subject.getPrincipals().removeAll(principalsForSubject);
            principalsInSubject = false;
        }
        return true;
    }


    public boolean logout() throws LoginException {
        return true;
    }

    private void throwLoginException(String msg) throws LoginException {
        throw new LoginException(msg);
    }

    private Callback[] getCallbacks() throws LoginException {
        if (callbackHandler == null) {
            throwLoginException("缺少callback处理器");
        }
        Callback[] callbacks = new Callback[1];
        try {
            callbackHandler.handle(callbacks);
        } catch (IOException e) {
            throw new LoginException(e.toString());
        } catch (UnsupportedCallbackException e) {
            throwLoginException(e.toString() + " " + e.getCallback().toString());
        }
        return callbacks;
    }

    private String getUserName(Callback[] callbacks) throws LoginException {
        String userName = ((NameCallback) callbacks[0]).getName();
        if (userName == null) {
            throwLoginException("Username为空.");
        }
        return userName;
    }


    private void addGroupsForSubject(String userName) {
        String groupName = "YufuPerimeterAtnUsers";
        System.out.println("\tgroupName\t= " + groupName);
        principalsForSubject.add(new WLSGroupImpl(groupName));
    }
}