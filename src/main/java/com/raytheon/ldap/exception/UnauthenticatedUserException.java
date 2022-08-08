package com.raytheon.ldap.exception;

import org.springframework.security.core.AuthenticationException;

public class UnauthenticatedUserException extends AuthenticationException {
	
	private static final String ERR_MSG = "UnAuthonticate User";
	
	public UnauthenticatedUserException() {
		super(ERR_MSG);
	}

}
