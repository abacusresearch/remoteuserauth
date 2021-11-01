# FishEyeHeaderAuthenticator
Header based Fisheye Authenticator to do SSO authentication via Kerberos and Apache's auth_kerb module.

# Compilation

- git clone this repo on your FishEye server
- run build.sh

# Installation

- Copy FishEyeHeaderAuthenticator.jar to `$FISHEYE_INST/lib/` (either from this repo or compile yourself from source)
- Add logger in `/opt/atlassian/fisheye/log4j.xml`
```
<logger name="com.cenqua.fisheye.user.plugin.FishEyeHeaderAuthenticator">
    <level value="DEBUG"/>
</logger>
```
- Bind FishEye to localhost in `$FISHEYE_INST/config.xml`
```
<http bind="127.0.0.1:8060"/>
```
- Restart FishEye
- Go to Security Settings > Authentication
- Click Setup Custom authentication
- Enter com.cenqua.fisheye.user.plugin.FishEyeHeaderAuthenticator as Classname
- Configure Apache (enable modules rewrite, headers and auth_kerb)
```
    <Virtualhost *:443>
     
            Servername ...
     
            ProxyRequests       Off
            ProxyPreserveHost   On
            ProxyPass           /       http://127.0.0.1:8060/
            ProxyPassReverse    /       http://127.0.0.1:8060/
     
            SSLEngine On
            SSLCertificateFile ...
            SSLCertificateKeyFile  ...
            SSLCaCertificateFile ...
     
            <Location />
                    AuthName "Kerberos SSO"
                    AuthType Kerberos
                    KrbAuthRealms ...
                    Krb5Keytab ...
                    KrbServiceName HTTP/...
                    KrbLocalUserMapping on
                    KrbMethodNegotiate on
                    KrbMethodK5Passwd on
                    Require valid-user
            </Location>

            # prevent the client from setting this header
            RequestHeader unset X-Forwarded-User
            
            # Adds the X-Forwarded-User header that indicates the current user name.
            RewriteEngine On
            RewriteCond %{REMOTE_USER} (.+)
            RewriteRule . - [E=RU:%1]
            RequestHeader set X-Forwarded-User %{RU}e
     
    </Virtualhost>
```

# Headers and debugging

Via the Properties field in the Custom Authenticator Settings you can define two optional settings:

- `authenticationHeader=<string>` : Header to use (should contain username known to FishEye). Note that `REMOTE_USER` does not work so rewrite `REMOTE_USER` to another header in Apache (see example). Defaults to X-Forwarded-User.
- `dumpHeaders=<boolean>` : When set to True all requests will be dumped in `$FISHEYE_INST/var/log/atlassian-fisheye-YYYY-MM-DD.log`. Defaults to False.

Use dumpHeaders only for debugging. It will write plain-text passwords in your log when no Kerberos ticket is available and user authenticated via HTTP Basic Auth fallback.

