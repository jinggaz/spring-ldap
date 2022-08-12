package com.raytheon.ldap.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.raytheon.ldap.auth.LdapTokenUtil;
import com.raytheon.ldap.dto.ResultForm;
import com.raytheon.ldap.entity.AuthenticateEntity;
import com.raytheon.ldap.exception.TokenRefreshException;
import com.raytheon.ldap.repository.AuthenticateRepository;

@Component
public class RefreshTokenService {

	@Autowired
	private LdapTokenUtil ldapTokenUtil;

	@Autowired
	private AuthenticateRepository authenticateRepository;

	@Value("${jwt.access-token.validity-time}")
	private int accessTokenValidityTime;

	public ResultForm refreshToken(String refreshToken) {

		return authenticateRepository.findByRefreshToken(refreshToken)
				.map(ldapTokenUtil::verifyTokenExpirationi)
				.map(AuthenticateEntity::getEmail)
				.map(emailAddress -> {
					final String accessToken = ldapTokenUtil.createAccessToken(emailAddress);
					return new ResultForm(accessToken, refreshToken);
				}).orElseThrow(() -> new TokenRefreshException(refreshToken, "Refresh token is not in database!"));

	}

}
