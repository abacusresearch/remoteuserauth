JIRA/Confluence/Fisheye/Bamboo HTTP Header SSO
==============================================
Goal
----
Users should transparently log in to JIRA/Confluence/Fisheye/Bamboo with SSO.

Overview
--------
Apache authenticates users using mod_auth_kerb and passes the authenticated username to JIRA/Confluence through an AJP proxy. JIRA/Confluence uses a custom Seraph filter which checks for the remote_user variable set by Apache and logs the user in automatically.

Build instructions
------------------

1. Get [Java SDK](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)
2. Get [atlassian SDK](https://developer.atlassian.com/server/framework/atlassian-sdk/set-up-the-atlassian-plugin-sdk-and-build-a-project/). following works on mac:

    ```shell
    brew tap atlassian/tap
    brew install atlassian/tap/atlassian-plugin-sdk
    atlas-version
    ```
3. Run command `atlas-package` in the RemoteUserConfluenceAuth` directory

```shell
export JAVA_HOME=/usr/lib/jvm/adoptopenjdk-8-hotspot-amd64/
wget https://marketplace.atlassian.com/download/plugins/atlassian-plugin-sdk-tgz
tar xf atlassian-plugin-sdk-tgz
mv atlassian-plugin-sdk-*.*.* atlassian-plugin-sdk
export PATH="$PATH:$(pwd)/atlassian-plugin-sdk/bin"
```


Installation
-----------
### JIRA
1. Install Jira using the standard install, listening on port 8080
   * Allow port 8080 through the firewall
2. Setup LDAP user directory
   * Test logging in using your AD credentials
3. Setup apache to act as a proxy to Jira using AJP
   * Add this line to the server.xml (/opt/atlassian/jira/conf/server.xml) file, around line 64. It should end up below the existing "Connector" entry.
     
     ```xml
     <Connector port="8009" redirectPort="8443" enableLookups="false" protocol="AJP/1.3" URIEncoding="UTF-8" tomcatAuthentication="false"/>
     ```
   * Check the "jira_proxy.conf" file in examples for the apache configuration.
4. Install mod_auth_kerb and configure it to authenticate against your AD
   * There is plenty of documentation out there on how to do this, I have also included my configuration files in the examples directory. (krb5.conf and smb.conf)
   * Set up a location like /private and test against that. Once Kerberos is authenticating properly there, apply it to the JIRA proxy created in the previous step.
5. Add the jar file (RemoteUserJiraAuth-X.Y.jar) to the WEB-INF/lib/ directory (by default it's /opt/atlassian/jira/atlassian-jira/WEB-INF/lib/)
   * Ensure that you've removed any older versions which may exist.
6. Edit WEB-INF/classes/seraph-config.xml and replace the existing authenticator with the custom one: 
   
   ```xml
   Comment this out:
   <authenticator class="com.atlassian.jira.security.login.JiraSeraphAuthenticator"/>
   Add this below it:
   <authenticator class="anguswarren.jira.RemoteUserJiraAuth"/>
   ```
7. Restart JIRA and Apache
8. Check to see if it is now working.

### Confluence
Use the JIRA instructions above with the following changes:

1. Use the base path of your Confluence installation rather than JIRA. (/opt/atlassian/confluence by default) 
2. If you're running both JIRA and Confluence on the same host, you'll need to use a different port for the AJP connector created in the server.xml file.
3. When you're replacing the authenticator classname in WEB-INF/classes/seraph-config.xml, use these details instead:
   
   ```xml
   Comment this out:
   <authenticator class="com.atlassian.confluence.user.ConfluenceAuthenticator"/>
   Add this below it:
   <authenticator class="anguswarren.confluence.RemoteUserConfluenceAuth"/>
   ```
