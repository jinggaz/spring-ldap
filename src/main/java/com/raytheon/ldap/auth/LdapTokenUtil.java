package com.raytheon.ldap.auth;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

@Component
public class LdapTokenUtil {

	private static final String HEADER_KEY = "Authorization";
	private static final String HEADER_VALUE = "Bearer ";

	private static final String ERR_MSG = "ERR_MSG";
	private static final String ERR_SIG_MSG = "Broken Token.";
	private static final String ERR_MAL_MSG = "Incorrect formatted Token.";
	private static final String ERR_EXP_MSG = "Expired Token.";
	private static final String ERR_UNS_MSG = "Not supported Token";
	private static final String ERR_ILL_MSG = "Has incorrect variable Token.";

	@Value("${jwt.secret}")
	private String secret;

	@Value("${jwt.validity_time}")
	private long validityTime;

	public String create(String email) {

		final long currentTime = System.currentTimeMillis();
		final long expiredTime = currentTime + validityTime;

		return Jwts.builder().setId(email).setIssuedAt(new Date(currentTime)).setExpiration(new Date(expiredTime))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	public String parse(HttpServletRequest request) {

		final String tokenHeader = request.getHeader(HEADER_KEY);
		String token = null;

		if (StringUtils.hasText(tokenHeader) && tokenHeader.startsWith(HEADER_VALUE)) {
			token = tokenHeader.substring(7);
		}

		return token;
	}

	public boolean validate(HttpServletRequest request, String token) {

		boolean isValid = false;

		try {
			Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
			isValid = true;
		} catch (SignatureException e) {
			request.setAttribute(ERR_MSG, ERR_SIG_MSG);
		} catch (MalformedJwtException e) {
			request.setAttribute(ERR_MSG, ERR_MAL_MSG);
		} catch (ExpiredJwtException e) {
			request.setAttribute(ERR_MSG, ERR_EXP_MSG);
		} catch (UnsupportedJwtException e) {
			request.setAttribute(ERR_MSG, ERR_UNS_MSG);
		} catch (IllegalArgumentException e) {
			request.setAttribute(ERR_MSG, ERR_ILL_MSG);
		}

		return isValid;
	}

	public String extractEmail(String token) {

		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getId();
	}

}
