需要自开发一个Provider来实现以下需求，在http header中如果包含YUFU_REMOTE_USER，那么value就是用户id，该请求视为已经过认证，就跟OAM的`OAM_REMOTE_USER`实现机制一样

> 大家可能觉得这种认证机制太弱智了，很容易有安全问题，所以这个方案的前提条件是，前面需要有认证中心的反向代理，不能让用户绕过认证中心进行访问，可以在防火墙层面将请求隔离

Provider是通过weblogic MBean实现，所以开发流程和和MBean基本一样

- 创建MBean描述文件

**YufuSSOIdentityAsserter.xml**

```xml
<?xml version="1.0" ?>
<!DOCTYPE MBeanType SYSTEM "commo.dtd">

<MBeanType
        Name="YufuSSOIdentityAsserter"
        DisplayName="YufuSSOIdentityAsserter"
        Package="com.yufu.plugin.weblogic"
        Extends="weblogic.management.security.authentication.IdentityAsserter"
        PersistPolicy="OnUpdate"
>
    <MBeanAttribute
            Name="ProviderClassName"
            Type="java.lang.String"
            Writeable="false"
            Preprocessor="weblogic.management.configuration.LegalHelper.checkClassName(value)"
            Default="&quot;com.yufu.plugin.weblogic.YufuSSOIdentityAsserterProviderImpl&quot;"
    />

    <MBeanAttribute
            Name="Description"
            Type="java.lang.String"
            Writeable="false"
            Default="&quot;得帆云weblogic认证插件&quot;"
    />

    <MBeanAttribute
            Name="Version"
            Type="java.lang.String"
            Writeable="false"
            Default="&quot;1.0&quot;"
    />

    <MBeanAttribute
            Name="SupportedTypes"
            Type="java.lang.String[]"
            Writeable="false"
            Default="new String[] { &quot;YUFU_REMOTE_USER&quot; }"
    />

    <MBeanAttribute
            Name="ActiveTypes"
            Type="java.lang.String[]"
            Default="new String[] { &quot;YUFU_REMOTE_USER&quot; }"
    />


    <MBeanAttribute
            Name="Base64DecodingRequired"
            Type="boolean"
            Writeable="false"
            Default="false"
            Description="See MyIdentityAsserter-doc.xml."
    />

</MBeanType>
```

该文件主要定义Provider的实现类和相关配置，定义在这里的属性在weblogic创建Provider时会显示在界面上，SupportedTypes表示支持的token类型，这里就是指token名称也就是http header名称，ActiveTypes表示默认选择的token类型。

- 准备以下三个java文件

**YufuSSOIdentityAsserterProviderImpl.java**

```java
package com.yufu.plugin.weblogic;

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
        options.put("IdentityAssertion", "true");
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
```

**YufuSSOLoginModuleImpl.java**

```java
package com.yufu.plugin.weblogic;
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
```

**YufuSSOCallbackHandlerImpl.java**

```java
package com.yufu.plugin.weblogic;
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
```

- 准备ant构建文件

**build.xml**

```xml
<project name="Expenselink Build" default="all" basedir=".">
<property name="fileDir" value="test" />

<target name="all" depends="build"/>

<target name="build" depends="clean,build.mdf,build.mjf"/>

<target name="clean">
<delete dir="${fileDir}" failonerror="false"/>
<delete file="YufuSSOIdentityAsserter.jar" failonerror="false"/>
<echo message="Clean finish" />
</target>

<!-- helper to build an MDF (mbean definition file) -->
<target name="build.mdf">
<java dir="${basedir}" fork="false" classname="weblogic.management.commo.WebLogicMBeanMaker">
<arg line="-files ${fileDir}" />
<arg value="-createStubs" />
<arg line="-MDF YufuSSOIdentityAsserter.xml" />
</java>
<echo message="Created Supporting Classes" />
</target>

<target name="build.mjf">

<copy todir="${fileDir}" flatten="true">
<fileset dir=".">
<include name="*.java" />
</fileset>
</copy>

<java dir="${basedir}" fork="false" classname="weblogic.management.commo.WebLogicMBeanMaker">
<arg line="-MJF YufuSSOIdentityAsserter.jar" />
<arg line="-files ${fileDir}" />
</java>
<echo message="Created Mbean Jar" />
</target>

</project>
```

将这些文件上传到weblogic服务器

```bash
$ ll
-rw-r--r-- 1 oracle oinstall  1102 May 11 10:03 build.xml
-rw-r--r-- 1 oracle oinstall   890 May 11 09:58 YufuSSOCallbackHandlerImpl.java
-rw-r--r-- 1 oracle oinstall  3194 May 11 10:34 YufuSSOIdentityAsserterProviderImpl.java
-rw-r--r-- 1 oracle oinstall  1576 May 11 09:58 YufuSSOIdentityAsserter.xml
-rw-r--r-- 1 oracle oinstall  4585 May 11 09:58 YufuSSOLoginModuleImpl.java
```

将`$MIDDLEWARE_HOME/wlserver_10.3/server/lib/mbeantypes/commo.dtd`文件复制到当前目录下

```bash
$ ll
-rw-r--r-- 1 oracle oinstall  1102 May 11 10:03 build.xml
-rw-r--r-- 1 oracle oinstall  7993 May 11 09:58 commo.dtd
-rw-r--r-- 1 oracle oinstall   890 May 11 09:58 YufuSSOCallbackHandlerImpl.java
-rw-r--r-- 1 oracle oinstall  3194 May 11 10:34 YufuSSOIdentityAsserterProviderImpl.java
-rw-r--r-- 1 oracle oinstall  1576 May 11 09:58 YufuSSOIdentityAsserter.xml
-rw-r--r-- 1 oracle oinstall  4585 May 11 09:58 YufuSSOLoginModuleImpl.java
```

- 设置weblogic上下文环境

```bash
cd $MIDDLEWARE_HOME/user_projects/domains/portal_domain/bin/
. ./setDomainEnv.sh
```

执行setDomainEnv.sh的目的是设置weblogic上下文环境，这样在后续的脚本执行过程中可以找到weblogic相关依赖jar包

> MIDDLEWARE_HOME：中间件目录，比如/u01/Middleware
>
> 命令的第二行第一个是有个点`.`，这个不能忽略

- 在build.xml目录下执行ant命令

```bash
$ ll
total 36
-rw-r--r-- 1 oracle oinstall 1102 May 11 10:03 build.xml
-rw-r--r-- 1 oracle oinstall 7993 May 11 09:58 commo.dtd
drwxr-xr-x 2 oracle oinstall 4096 May 11 13:00 src
-rw-r--r-- 1 oracle oinstall  890 May 11 09:58 YufuSSOCallbackHandlerImpl.java
-rw-r--r-- 1 oracle oinstall 3194 May 11 10:34 YufuSSOIdentityAsserterProviderImpl.java
-rw-r--r-- 1 oracle oinstall 1576 May 11 09:58 YufuSSOIdentityAsserter.xml
-rw-r--r-- 1 oracle oinstall 4585 May 11 09:58 YufuSSOLoginModuleImpl.java


$ ant
Buildfile: build.xml

clean:
   [delete] Deleting directory /data/Middleware/user_projects/domains/portal_domain/assert/yufu/src
     [echo] Clean finish

build.mdf:
     [java] Working directory ignored when same JVM is used.
     [java] Parsing the MBean definition file: YufuSSOIdentityAsserter.xml
     [echo] Created Supporting Classes

build.mjf:
     [copy] Copying 3 files to /data/Middleware/user_projects/domains/portal_domain/assert/yufu/src
     [java] Working directory ignored when same JVM is used.
     [java] Creating an MJF from the contents of directory src...
     [java] Compiling the files...
     [java] Creating the list.
     [java] Doing the compile.
    .....
build:

all:

BUILD SUCCESSFUL
Total time: 5 seconds
```

构建成功后会在本地生成一个jar文件，将该文件拷本到以下目录

```bash
cp YufuSSOIdentityAsserter.jar $MIDDLEWARE_HOME/wlserver_10.3/server/lib/mbeantypes/
```

> weblogic本身自带了ant工具，路径位于$MIDDLEWARE_HOME/modules/org.apache.ant_1.7.1目录下，你可以在用户的.bash_profile里面加入以下配置
>
> ANT_HOME=/data/Middleware/modules/org.apache.ant_1.7.1
>
> PATH=$ANT_HOME/bin:$PATH
>
> 这样就可以直接使用ant命令

- 重启所有服务器（AdminServer和ManagerServer）

## 配置Provider

登录console，进入`myrealm >Providers`就可以看到自开发的Asserter

![](http://zhengjianfeng.cn/images/BjhAAbc0T264R8jKtMUBRhUNTzCeA2jU.jpg)

![](http://zhengjianfeng.cn/images/gCNm3tH7crkhZ29S5uc7gKd84hDYOZoi.jpg)

点击Save保存，点击激活更改应用所有更改

- 碰到的问题

在激活的时候可能会碰到一下错误

![](http://zhengjianfeng.cn/images/dw9dCi9llYtNgOAEE2lHjUgdpvPC5MoY.jpg)

后台报错如下：

```bash
<May 10, 2021 4:54:50 PM CST> <Error> <Console> <BEA-240003> <Console encountered the following error weblogic.management.provider.UpdateException: [Management:141191]The prepare phase of the configuration update failed with an exception:
 at weblogic.management.provider.internal.RuntimeAccessDeploymentReceiverService.updateDeploymentContext

 ...

Caused by: java.io.IOException: [Management:141245]Schema Validation Error in config/config.xml see log for details. Schema validation can be disabled by starting the server with the command line option: -Dweblogic.configuration.schemaValidationEnabled=false
 at weblogic.management.provider.internal.EditAccessImpl.checkErrors(EditAccessImpl.java:2340)
 at weblogic.management.provider.internal.RuntimeAccessDeploymentReceiverService.handleConfigTreeLoad(RuntimeAccessDeploymentReceiverService.java:968)
 at weblogic.management.provider.internal.RuntimeAccessDeploymentReceiverService.updateDeploymentContext(RuntimeAccessDeploymentReceiverService.java:599)
>
```

这个错误是配置完provider后，weblogic会将信息写入config/config.xml文件中，而该文件在Schema validation（模式验证）中验证不通过，这应该是weblogic的bug导致，解决方法是在setDomainEnv.sh中找到这段（大概在530行左右）

```bash
JAVA_OPTIONS="${JAVA_OPTIONS}"
export JAVA_OPTIONS
```

将其改为

```bash
JAVA_OPTIONS="${JAVA_OPTIONS} -Dweblogic.configuration.schemaValidationEnabled=false"
export JAVA_OPTIONS
```

然后重启所有的服务器

## 验证

- 准备一个servlet，代码如下

```java
public class SecurityServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        StringBuffer str = new StringBuffer();
        str.append("remoteUser:" + req.getRemoteUser() + "\r\n<br/>");
        String name = (req.getUserPrincipal() == null) ? null : req
                .getUserPrincipal().getName();
        str.append("Principal Name: " + name + "\r\n<br/>");
        str.append("Authentication Type: " + req.getAuthType() + "\n<br/>");
        resp.setCharacterEncoding("utf-8");
        resp.setContentType("text/html; charset=UTF-8");
        resp.getOutputStream().write(str.toString().getBytes("utf-8"));
        resp.getOutputStream().flush();
    }
}
```

- web.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"
         version="2.5" xmlns="http://java.sun.com/xml/ns/javaee">
    <servlet>
        <servlet-name>security</servlet-name>
        <servlet-class>com.demo.service.SecurityServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>security</servlet-name>
        <url-pattern>/security</url-pattern>
    </servlet-mapping>
   
    <security-constraint>
        <web-resource-collection>
            <web-resource-name>SecurePages</web-resource-name>
            <url-pattern>/*</url-pattern>
            <http-method>GET</http-method>
        </web-resource-collection>
        <auth-constraint>
            <role-name>ValidUser</role-name>
        </auth-constraint>
        <user-data-constraint>
            <transport-guarantee>NONE</transport-guarantee>
        </user-data-constraint>
    </security-constraint>
    <login-config>
        <auth-method>CLIENT-CERT</auth-method>
        <realm-name>myrealm</realm-name>
    </login-config>
    <security-role>
        <role-name>ValidUser</role-name>
    </security-role>
</web-app>
```

- weblogi.xml

```xml
<?xml version='1.0' encoding='UTF-8'?>
<wls:weblogic-web-app
        xmlns:wls="http://xmlns.oracle.com/weblogic/weblogic-web-app"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://java.sun.com/xml/ns/javaee
		http://java.sun.com/xml/ns/javaee/ejb-jar_3_0.xsd
		http://xmlns.oracle.com/weblogic/weblogic-web-app
		http://xmlns.oracle.com/weblogic/weblogic-web-app/1.4/weblogic-web-app.xsd">
    <wls:security-role-assignment>
        <wls:role-name>ValidUser</wls:role-name>
        <wls:principal-name>users</wls:principal-name>
    </wls:security-role-assignment>
    <wls:context-root>/definetool</wls:context-root>
</wls:weblogic-web-app>

```

- 部署

将应用打包war部署weblogic

- 测试

```bash
➜  curl -v http://47.111.230.1:7001/definetool/security

*   Trying 47.111.230.1...
* TCP_NODELAY set
* Connected to 47.111.230.1 (47.111.230.1) port 7001 (#0)
> GET /definetool/security HTTP/1.1
> Host: 47.111.230.1:7001
> User-Agent: curl/7.54.0
> Accept: */*
> 
< HTTP/1.1 401 Unauthorized
< Date: Tue, 11 May 2021 11:57:20 GMT
< Content-Length: 1468
< Content-Type: text/html; charset=UTF-8
< 
```

加上token（token名称为YUFU_REMOTE_USER)定义在配置文件里

```bash
➜ curl -v http://47.111.230.1:7001/definetool/security -H 'YUFU_REMOTE_USER:helen'

*   Trying 47.111.230.1...
* TCP_NODELAY set
* Connected to 47.111.230.1 (47.111.230.1) port 7001 (#0)
> GET /definetool/security HTTP/1.1
> Host: 47.111.230.1:7001
> User-Agent: curl/7.54.0
> Accept: */*
> YUFU_REMOTE_USER:helen
> 
< HTTP/1.1 200 OK
< Date: Tue, 11 May 2021 11:59:31 GMT
< Transfer-Encoding: chunked
< Content-Type: text/html; charset=UTF-8
< X-ORACLE-DMS-ECID: c813593f0a2fd3cb:70daab41:17959480e1c:-8000-0000000000000034
< Set-Cookie: JSESSIONID=JNNbS-fvPiFe2u2upP13qyykiOvQ8IlLLLxd7m2_GSWEhlwUQlrd!686904248; path=/; HttpOnly
< 
remoteUser:helen
<br/>Principal Name: helen
<br/>Authentication Type: CLIENT_CERT
* Connection #0 to host 47.111.230.1 left intact
<br/>%                                                      
```