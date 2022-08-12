package com.raytheon.ldap.entity;

import java.util.Date;

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

	private String email;
	
	private Date expiryDate;

	public AuthenticateEntity() {

	}

	private AuthenticateEntity(String refreshToken, String email, Date expiryDate) {
		this.refreshToken = refreshToken;
		this.email = email;
		this.expiryDate = expiryDate;
	}

	public static AuthenticateEntity createEntity(String refreshToken, String email, Date expiryDate) {
		return new AuthenticateEntity(refreshToken, email, expiryDate);
	}

	public Long getId() {
		return id;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public String getEmail() {
		return email;
	}

	public Date getExpiryDate() {
		return expiryDate;
	}

	public void refreshUpdate(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public void changeToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
}
