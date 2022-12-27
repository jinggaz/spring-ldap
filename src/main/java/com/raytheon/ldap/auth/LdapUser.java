package com.raytheon.ldap.auth;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class LdapUser implements UserDetails {

	private static final long serialVersionUID = 492395929795162440L;
	
	private String email;
	private String fullName;
	private String password;
	private Collection<? extends GrantedAuthority> authorities;

	public LdapUser(String email, String name, Collection<? extends GrantedAuthority> authorities) {
		this.email = email;
		this.fullName = name;
		this.authorities = authorities;
	}

	public LdapUser(String email, String name, String password, Collection<? extends GrantedAuthority> authorities) {
		this.email = email;
		this.fullName = name;
		this.password = password;
		this.authorities = authorities;
	}
	
	public String getEmail() {
		return email;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return email;
	}

	public String getfullName() {
		return fullName;
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
