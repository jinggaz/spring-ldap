package com.raytheon.ldap.auth;

import java.util.Date;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.raytheon.ldap.entity.AuthenticateEntity;
import com.raytheon.ldap.exception.TokenRefreshException;
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

	@Value("${jwt.access-token.validity-time}")
	private int accessTokenValidityTime;

	@Value("${jwt.access-token.secret}")
	private String accessSecret;

	@Value("${jwt.refresh-token.validity-time}")
	private int refreshTokenValidityTime;

	@Value("${jwt.refresh-token.secret}")
	private String refreshSecret;

	public String createAccessToken(String email) {
		return Jwts.builder().setId(email).setIssuedAt(new Date())
				.setExpiration(createExpiryDate(accessTokenValidityTime))
				.signWith(SignatureAlgorithm.HS512, accessSecret).compact();
	}

	public String createRefreshToken(String email) {
		return Jwts.builder().setId(email).setIssuedAt(new Date())
				.setExpiration(createExpiryDate(refreshTokenValidityTime))
				.signWith(SignatureAlgorithm.HS512, refreshSecret).compact();
	}

	private Date createExpiryDate(int validityTime) {
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

	public boolean validateAccessToken(HttpServletRequest request, String token) {

		boolean isValid = false;

		try {
			Jwts.parser().setSigningKey(accessSecret).parseClaimsJws(token);
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

	public String extractEmailFromAccessToken(String accessToken) {
		return Jwts.parser().setSigningKey(accessSecret).parseClaimsJws(accessToken).getBody().getId();
	}

	public String extractEmailFromRefreshToken(AuthenticateEntity authenticateEntity) {
		return Jwts.parser().setSigningKey(refreshSecret).parseClaimsJws(authenticateEntity.getRefreshToken()).getBody().getId();
	}

	public Date extractExpirationFromAccessToken(String accessToken) {
		return Jwts.parser().setSigningKey(accessSecret).parseClaimsJws(accessToken).getBody().getExpiration();
	}

	public Date extractExpirationFromRefreshToken(String refreshToken) {
		return Jwts.parser().setSigningKey(refreshSecret).parseClaimsJws(refreshToken).getBody().getExpiration();
	}

	public AuthenticateEntity verifyTokenExpiration(AuthenticateEntity authenticateEntity) {
		final Date expiryDate = extractExpirationFromRefreshToken(authenticateEntity.getRefreshToken());
		if (expiryDate.compareTo(new Date()) < 0) {
			authenticateRepository.delete(authenticateEntity);
			throw new TokenRefreshException(authenticateEntity.getRefreshToken(),
					"Refresh token was expired. Please make a new signin request");
		}

		return authenticateEntity;
	}

}
