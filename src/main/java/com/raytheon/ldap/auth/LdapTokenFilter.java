package com.raytheon.ldap.auth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.raytheon.ldap.service.UserService;

@Component
public class LdapTokenFilter extends OncePerRequestFilter {

	@Autowired
	private UserService userService;

	@Autowired
	private LdapTokenUtil ldapTokenUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		final String token = ldapTokenUtil.parse(request);
		if (token != null && ldapTokenUtil.validateAccessToken(request, token)) {
			final String email = ldapTokenUtil.extractEmailFromAccessToken(token);
			final LdapUser user = (LdapUser) userService.loadUserByEmail(email);
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user,
					null, user.getAuthorities());
			authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		}
		filterChain.doFilter(request, response);
	}

}
