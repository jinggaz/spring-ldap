package com.raytheon.ldap.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.raytheon.ldap.auth.LdapTokenUtil;
import com.raytheon.ldap.auth.LdapUser;
import com.raytheon.ldap.dto.LoginForm;
import com.raytheon.ldap.dto.ResultForm;
import com.raytheon.ldap.entity.AuthenticateEntity;
import com.raytheon.ldap.exception.UserNotFoundException;
import com.raytheon.ldap.repository.AuthenticateRepository;

@Component
public class UserService {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private LdapTokenUtil ldapTokenUtil;

	@Autowired
	private AuthenticateRepository authenticateRepository;

	@Autowired
	private LdapTemplate ldapTemplate;

	private static final String ROLE_PREFIX = "ROLE_";
	private static final String UID = "uid";
	private static final String CN = "cn";
	private static final String OU = "ou";
	private static final String USERPASSWORD = "userPassword";

	public boolean authenticate(String email, String rawPassword) {
		LdapQuery ldapQuery = LdapQueryBuilder.query().where(UID).is(email);

		List<LoginForm> user = ldapTemplate.search(ldapQuery, new AbstractContextMapper<LoginForm>() {
			@Override
			protected LoginForm doMapFromContext(DirContextOperations ctx) {
				final String eamil = ctx.getStringAttribute(UID);
				final byte[] bytes = (byte[]) ctx.getObjectAttribute(USERPASSWORD);
				final String password = new String(bytes);
				return new LoginForm(email, password);
			}

		});
		if (user.size() != 1) {
			throw new UserNotFoundException();
		}

		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

		return passwordEncoder.matches(rawPassword, user.get(0).getPassword()) ? true : false;
	}

	public UserDetails loadUserByEmail(String email) {
		LdapQuery ldapQuery = LdapQueryBuilder.query().where(UID).is(email);

		List<LdapUser> user = ldapTemplate.search(ldapQuery, new AbstractContextMapper<LdapUser>() {
			@Override
			protected LdapUser doMapFromContext(DirContextOperations ctx) {
				final String eamil = ctx.getStringAttribute(UID);
				final String name = ctx.getStringAttribute(CN);
				List<GrantedAuthority> authorities = new ArrayList<>();
				authorities.add(new SimpleGrantedAuthority(
						ROLE_PREFIX + LdapUtils.getStringValue(ctx.getDn(), OU).toUpperCase()));
				return new LdapUser(email, name, authorities);
			}

		});
		if (user.size() != 1) {
			throw new UserNotFoundException();
		}

		return user.get(0);
	}

	public ResultForm login(LoginForm loginForm) {
		final Authentication authentication = getAuthenticationFromLoginForm(loginForm);
		final ResultForm resultForm = createAccessAndRefreshToken(authentication);

		return resultForm;
	}

	private ResultForm createAccessAndRefreshToken(Authentication authentication) {
		final LdapUser user = (LdapUser) authentication.getPrincipal();
		final String accessToken = ldapTokenUtil.createAccessToken(user.getEmail());
		final String refreshToken = ldapTokenUtil.createRefreshToken(user.getEmail());

		Optional<AuthenticateEntity> authenticateEntity = authenticateRepository.findByEmail(user.getEmail());
		if (authenticateEntity.isPresent()) {
			authenticateEntity.get().changeToken(refreshToken);
			authenticateRepository.save(authenticateEntity.get());
		} else {
			authenticateRepository.save(AuthenticateEntity.createEntity(refreshToken, user.getEmail(),
					ldapTokenUtil.extractExpirationFromRefreshToken(refreshToken)));
		}

		return new ResultForm(accessToken, refreshToken);
	}

	private Authentication getAuthenticationFromLoginForm(LoginForm loginForm) {
		final String email = loginForm.getEmail();
		final String password = loginForm.getPassword();

		return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
	}

}
