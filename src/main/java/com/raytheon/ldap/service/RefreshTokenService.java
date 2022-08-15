package com.raytheon.ldap.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.raytheon.ldap.auth.LdapTokenUtil;
import com.raytheon.ldap.dto.ResultForm;
import com.raytheon.ldap.exception.TokenRefreshException;
import com.raytheon.ldap.repository.AuthenticateRepository;

@Component
public class RefreshTokenService {

	@Autowired
	private LdapTokenUtil ldapTokenUtil;

	@Autowired
	private AuthenticateRepository authenticateRepository;

	public ResultForm refreshToken(String refreshToken) {

		return authenticateRepository.findByRefreshToken(refreshToken)
				.map(ldapTokenUtil::verifyRefreshTokenExpiration)
				.map(ldapTokenUtil::extractEmailFromRefreshToken)
				.map(email -> {
					final String accessToken = ldapTokenUtil.createAccessToken(email);
					return new ResultForm(accessToken, refreshToken);
				}).orElseThrow(() -> new TokenRefreshException(refreshToken, "Refresh token is not in database!"));
	}

}
