package com.raytheon.ldap.dto;

public class ResultForm {

	private Object accessToken;

	private Object refreshToken;

	public ResultForm() {

	}

	public ResultForm(Object accessToken, Object refreshToken) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
	}

	public Object getAccessToken() {
		return accessToken;
	}

	public Object getRefreshToken() {
		return refreshToken;
	}

}
