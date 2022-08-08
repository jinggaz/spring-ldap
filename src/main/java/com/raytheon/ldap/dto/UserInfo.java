package com.raytheon.ldap.dto;

public class UserInfo {

	private String email;
	private String name;
	private String group;

	public UserInfo(String email, String name, String group) {
		this.email = email;
		this.name = name;
		this.group = group;
	}

	public String getEmail() {
		return email;
	}

	public String getName() {
		return name;
	}

	public String getGroup() {
		return group;
	}

}
