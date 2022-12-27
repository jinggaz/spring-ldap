package com.raytheon.ldap.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.raytheon.ldap.auth.LdapUser;
import com.raytheon.ldap.exception.UserNotFoundException;

@Component
public class UserService {

	@Autowired
	private LdapTemplate ldapTemplate;

	private static final String ROLE_PREFIX = "ROLE_";

	public LdapUser authenticate(String email, String rawPassword) {

		LdapQuery ldapQuery = LdapQueryBuilder.query().where("uid").is(email);

		List<LdapUser> user = ldapTemplate.search(ldapQuery, new AbstractContextMapper<LdapUser>() {
			@Override
			protected LdapUser doMapFromContext(DirContextOperations ctx) {
				final String uid = getUidFromDirContextOperations(ctx);
				final String fullName = getFullNameFromDirContextOperations(ctx);
				final String password = getPasswordFromDirContextOperations(ctx);

				final List<GrantedAuthority> authorities = getGrantedAuthoritiesFromDirContextOperations(ctx);
				return new LdapUser(uid, fullName, password, authorities);
			}
		});

		if (user.size() != 1) {
			throw new UserNotFoundException();
		}

		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

		return passwordEncoder.matches(rawPassword, user.get(0).getPassword()) ? user.get(0) : null;
	}

	public UserDetails loadUserByEmail(String email) {

		LdapQuery ldapQuery = LdapQueryBuilder.query().where("uid").is(email);

		List<LdapUser> user = ldapTemplate.search(ldapQuery, new AbstractContextMapper<LdapUser>() {
			@Override
			protected LdapUser doMapFromContext(DirContextOperations ctx) {
				final String uid = getUidFromDirContextOperations(ctx);
				final String fullName = getFullNameFromDirContextOperations(ctx);

				List<GrantedAuthority> authorities = getGrantedAuthoritiesFromDirContextOperations(ctx);
				return new LdapUser(uid, fullName, authorities);
			}
		});

		if (user.size() != 1) {
			throw new UserNotFoundException();
		}

		return user.get(0);
	}

	private String getUidFromDirContextOperations(DirContextOperations ctx) {
		return ctx.getStringAttribute("uid");
	}

	private String getFullNameFromDirContextOperations(DirContextOperations ctx) {
		return ctx.getStringAttribute("cn");
	}

	private String getPasswordFromDirContextOperations(DirContextOperations ctx) {
		final byte[] bytes = (byte[]) ctx.getObjectAttribute("userPassword");
		return new String(bytes);
	}

	private List<GrantedAuthority> getGrantedAuthoritiesFromDirContextOperations(DirContextOperations ctx) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		authorities.add(
				new SimpleGrantedAuthority(ROLE_PREFIX + LdapUtils.getStringValue(ctx.getDn(), "cn").toUpperCase()));
		return authorities;
	}

}
