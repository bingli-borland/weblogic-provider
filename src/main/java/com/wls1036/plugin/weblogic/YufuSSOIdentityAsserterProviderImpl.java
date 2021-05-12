package com.wls1036.plugin.weblogic;

import java.util.HashMap;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import weblogic.management.security.ProviderMBean;
import weblogic.security.provider.PrincipalValidatorImpl;
import weblogic.security.service.ContextHandler;
import weblogic.security.spi.*;

public final class YufuSSOIdentityAsserterProviderImpl implements AuthenticationProviderV2, IdentityAsserterV2 {
    final static private String TOKEN_TYPE = "YUFU_REMOTE_USER";

    private String description;
    private LoginModuleControlFlag controlFlag;


    public void initialize(ProviderMBean mbean, SecurityServices services) {
        System.out.println("插件初始化");
        YufuSSOIdentityAsserterMBean asserterBean = (YufuSSOIdentityAsserterMBean) mbean;
        description = asserterBean.getDescription() + "\n" + asserterBean.getVersion();
        controlFlag = LoginModuleControlFlag.SUFFICIENT;
    }

    /**
     * 核心认证逻辑
     *
     * @param type    token名称
     * @param token   token值（byte[]类型）
     * @param context
     * @return
     * @throws IdentityAssertionException
     */
    public CallbackHandler assertIdentity(String type, Object token, ContextHandler context) throws IdentityAssertionException {
        System.out.println("\tType\t\t= " + type);
        System.out.println("\tToken\t\t= " + token);
        this.validate(type, token);
        byte[] tokenBytes = (byte[]) token;
        if (tokenBytes == null || tokenBytes.length < 1) {
            String error = "received empty token byte array";
            throw new IdentityAssertionException(error);
        }
        String userName = new String(tokenBytes);
        return new YufuSSOCallbackHandlerImpl(userName);
    }

    private void validate(String type, Object token) throws IdentityAssertionException {
        if (!(TOKEN_TYPE.equals(type))) {
            String error = "unknown token type \"" + type + "\"." + " Expected " + TOKEN_TYPE;
            throw new IdentityAssertionException(error);
        }

        if (!(token instanceof byte[])) {
            String error = "received unknown token class \"" + token.getClass() + "\"." + " Expected a byte[].";
            System.out.println("\tError: " + error);
            throw new IdentityAssertionException(error);
        }
    }


    public AppConfigurationEntry getLoginModuleConfiguration() {
        HashMap options = new HashMap();
        return getConfiguration(options);
    }

    /**
     * 定义LoginModule实现类
     *
     * @param options
     * @return
     */
    private AppConfigurationEntry getConfiguration(HashMap options) {
        return new
                AppConfigurationEntry(
                "com.yufu.plugin.weblogic.YufuSSOLoginModuleImpl",
                controlFlag,
                options
        );
    }

    public AppConfigurationEntry getAssertionModuleConfiguration() {
        HashMap options = new HashMap();
        return getConfiguration(options);
    }

    public PrincipalValidator getPrincipalValidator() {
        return new PrincipalValidatorImpl();
    }

    public String getDescription() {
        return description;
    }

    public void shutdown() {
    }

    public IdentityAsserterV2 getIdentityAsserter() {
        return this;
    }

}
