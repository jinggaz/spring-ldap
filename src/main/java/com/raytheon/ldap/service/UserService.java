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
import com.raytheon.ldap.dto.LoginForm;
import com.raytheon.ldap.exception.UserNotFoundException;

@Component
public class UserService {

	@Autowired
	private LdapTemplate ldapTemplate;
	
	private static final String ROLE_PREFIX = "ROLE_";
	
	public boolean authenticate(String email, String rawPassword) {

		LdapQuery ldapQuery = LdapQueryBuilder.query().where("uid").is(email);
		
		List<LoginForm> user = ldapTemplate.search(ldapQuery, new AbstractContextMapper<LoginForm>() {

			@Override
			protected LoginForm doMapFromContext(DirContextOperations ctx) {
				final String eamil = ctx.getStringAttribute("uid");
				final byte[] bytes = (byte[]) ctx.getObjectAttribute("userPassword");
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

		LdapQuery ldapQuery = LdapQueryBuilder.query().where("uid").is(email);

		List<LdapUser> user = ldapTemplate.search(ldapQuery, new AbstractContextMapper<LdapUser>() {

			@Override
			protected LdapUser doMapFromContext(DirContextOperations ctx) {
				final String eamil = ctx.getStringAttribute("uid");
				final String name = ctx.getStringAttribute("cn");
				List<GrantedAuthority> authorities = new ArrayList<>();
				authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + LdapUtils.getStringValue(ctx.getDn(), "ou").toUpperCase()));
				return new LdapUser(email, name, authorities);
			}
			
		});
		if (user.size() != 1) {
			throw new UserNotFoundException();
		}
		
		return user.get(0);
	}

}
