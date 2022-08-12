package com.raytheon.ldap.auth;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.raytheon.ldap.entity.AuthenticateEntity;
import com.raytheon.ldap.exceptioni.TokenRefreshException;
import com.raytheon.ldap.repository.AuthenticateRepository;

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

	@Autowired
	private AuthenticateRepository authenticateRepository;

	@Value("${jwt.secret}")
	private String secret;

	public String createToken(int validityTime, String email) {
		return Jwts.builder().setId(email).setIssuedAt(new Date()).setExpiration(createExpireDate(validityTime))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	private Date createExpireDate(int validityTime) {
		return new Date((new Date()).getTime() + validityTime);
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

	public Date extractExpiration(String token) {

		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getExpiration();
	}

	public AuthenticateEntity verifyTokenExpirationi(AuthenticateEntity authenticateEntity) {

		if (authenticateEntity.getExpiryDate().compareTo(new Date()) < 0) {
			authenticateRepository.delete(authenticateEntity);
			throw new TokenRefreshException(authenticateEntity.getRefreshToken(),
					"Refresh token was expired. Please make a new signin request");
		}

		return authenticateEntity;
	}

}
