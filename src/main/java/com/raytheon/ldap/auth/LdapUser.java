package com.raytheon.ldap.auth;

import java.util.ArrayList;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class LdapUser implements UserDetails {

	private static final long serialVersionUID = 492395929795162440L;

	private String email;
	private String name;
	private Collection<? extends GrantedAuthority> authorities;

	public LdapUser() {

	}

	public LdapUser(String email, String name, Collection<? extends GrantedAuthority> authorities) {
		this.email = email;
		this.name = name;
		this.authorities = authorities;
	}

	public String getEmail() {
		return email;
	}

	public String getName() {
		return name;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public String getUsername() {
		return email;
	}

	@Override
	public boolean isAccountNonExpired() {
		return false;
	}

	@Override
	public boolean isAccountNonLocked() {
		return false;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return false;
	}

	@Override
	public boolean isEnabled() {
		return false;
	}

}
