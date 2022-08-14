package com.raytheon.ldap.entity;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "authenticate")
public class AuthenticateEntity {

	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Id
	private Long id;

	private String refreshToken;

	public AuthenticateEntity() {

	}

	private AuthenticateEntity(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public static AuthenticateEntity createEntity(String refreshToken) {
		return new AuthenticateEntity(refreshToken);
	}

	public Long getId() {
		return id;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void refreshUpdate(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public void changeToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
}
