/**
 *  Copyright 2018 Geert Lorang
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package com.cenqua.fisheye.user.plugin;

import org.apache.log4j.Logger;
import java.util.Properties;
import java.util.Enumeration;
import javax.servlet.http.HttpServletRequest;

/**
 * Always grants access via header set in authenticationHeader property (default X-Forwarded-User)
 */
public class FishEyeHeaderAuthenticator extends AbstractFishEyeAuthenticator {

	private static class HeaderAuthToken implements AuthToken {
		private final String name;
		
		public HeaderAuthToken(String name) {
			this.name = name;
		}
		
		public String getUsername() {
			return name;
		}
	
		public String getDisplayName() {
			return null;
		}

		public String getEmail() {
			return null;
		}
	}

	private static final Logger log = Logger.getLogger(FishEyeHeaderAuthenticator.class);
	private String authenticationHeader;
	private boolean dumpHeaders;

	public AuthToken checkRequest(HttpServletRequest request) {

		String remoteUser = request.getHeader(authenticationHeader);
		log.debug("Authenticating " + remoteUser + "(" + authenticationHeader + ")");

		// dump all headers in request
		if(dumpHeaders) {
			Enumeration<String> headerNames = request.getHeaderNames();
			while(headerNames.hasMoreElements()) {
				String headerName = headerNames.nextElement();
				log.debug("Header: " + headerName + ", value: " + request.getHeader(headerName));
			}
		}

		if(remoteUser != null) {
			return new HeaderAuthToken(remoteUser);
		}

		return null;
	}
	
	public boolean isRequestUserStillValid(String username, HttpServletRequest req) {
		return true;
	}

	public void init(Properties cfg) {

		log.debug("init: " + cfg);

		authenticationHeader = (cfg.getProperty("authenticationHeader") == null) ? "X-Forwarded-User" : cfg.getProperty("authenticationHeader");
		dumpHeaders = (cfg.getProperty("dumpHeaders") == null) ? false : Boolean.parseBoolean(cfg.getProperty("dumpHeaders"));

		log.debug("Users will be authenticated via header: " + authenticationHeader + " dumpHeaders = " + dumpHeaders);
	}

	public void close() {}

	public AuthToken checkPassword(String username, String password) {
		log.debug("In checkPassword() - Returning new HeaderAuthToken(" + username + ") password: " + password);
		return new HeaderAuthToken(username);
	}

	public AuthToken recreateAuth(String username) {
		log.debug("In recreateAuth() - Returning new HeaderAuthToken(" + username + ")");
		return new HeaderAuthToken(username);
	}
	
	// always return false here, authorization is done based on group membership
	public boolean hasPermissionToAccess(AuthToken tok, String repname, String constraint) {
		log.debug("returning false for hasPermissionToAccess(" + tok + ", " + repname + ", " + constraint + ")");
		return false;
	}
}
