package com.raytheon.ldap.exception;

public class UserNotFoundException extends RuntimeException {

	private static final long serialVersionUID = 547450958536568092L;

	private static final String ERR_MSG = "No user exist";

	public UserNotFoundException() {
		super(ERR_MSG);
	}

}
