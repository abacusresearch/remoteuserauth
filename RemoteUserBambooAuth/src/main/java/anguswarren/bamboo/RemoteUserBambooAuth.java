/**
 * Copyright 2016 Angus Warren
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package anguswarren.bamboo;

import org.apache.log4j.Category;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Properties;
import java.security.Principal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import com.atlassian.core.util.ClassLoaderUtils;
import com.atlassian.bamboo.user.authentication.BambooAuthenticator;

public class RemoteUserBambooAuth extends BambooAuthenticator {
    private static final Category log = Category.getInstance(RemoteUserBambooAuth.class);
	
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        Principal user = null;
        try {
            if (request.getSession() != null && request.getSession().getAttribute(BambooAuthenticator.LOGGED_IN_KEY) != null) {
                log.debug("Session found; user already logged in");
                user = (Principal) request.getSession().getAttribute(BambooAuthenticator.LOGGED_IN_KEY);
            } else {
                Properties p = new Properties();
                try {
                    InputStream iStream = ClassLoaderUtils.getResourceAsStream("RemoteUserBambooAuth.properties", this.getClass());
                    p.load(iStream);
                } catch (Exception e) {
                    log.debug("Exception loading propertie. The properties file is optional anyway, so this may not be an issues: " + e, e);
                }

                String trustedhosts = p.getProperty("trustedhosts");
                if (trustedhosts != null) {
                    String ipAddress = request.getRemoteAddr();
                    if (Arrays.asList(trustedhosts.split(",")).contains(ipAddress)) {
                        log.debug("IP found in trustedhosts.");
                    } else {
                        log.debug("IP not found in trustedhosts: " + ipAddress);
                        return null; 
                    }
                } else {
                    log.debug("trustedhosts not configured. If you're using http headers, this may be a security issue.");
                }

                String remoteuser = null;
                String header = p.getProperty("header");
                if (header == null) {
                    log.debug("Trying REMOTE_USER for SSO");
                    remoteuser = request.getRemoteUser();
                } else {
                    log.debug("Trying HTTP header '" + header + "' for SSO");
                    remoteuser = request.getHeader(header);
                }

                if (remoteuser != null) {
                    user = getUser(remoteuser);
                    log.debug("Logging in with username: " + user);
                    request.getSession().setAttribute(BambooAuthenticator.LOGGED_IN_KEY, user);
                    request.getSession().setAttribute(BambooAuthenticator.LOGGED_OUT_KEY, null);
                } else {
                    log.debug("remote_user is null");
                    return null;
                }
            }
        } catch (Exception e) {
            log.error("Exception: " + e, e);
        }
        return user;
    }
}
