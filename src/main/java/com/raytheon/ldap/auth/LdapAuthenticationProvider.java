package com.raytheon.ldap.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.raytheon.ldap.exception.UnauthenticatedUserException;
import com.raytheon.ldap.service.UserService;

@Component
public class LdapAuthenticationProvider implements AuthenticationProvider {
	
	@Autowired
	private UserService userService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		final String email = authentication.getName();
		final String password = (String) authentication.getCredentials();
		
		final boolean isAuthenticated = userService.authenticate(email, password);
		
		if (!isAuthenticated) {
			throw new UnauthenticatedUserException();
		} else {
			LdapUser user = (LdapUser) userService.loadUserByEmail(email);
			return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
	}

}
