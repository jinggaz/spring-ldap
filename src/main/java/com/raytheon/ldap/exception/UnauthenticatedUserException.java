package com.raytheon.ldap.exception;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class UnauthenticatedUserException extends AuthenticationException {

	private static final long serialVersionUID = -5158091651471266888L;

	private static final String ERR_MSG = "UnAuthonticate User";

	public UnauthenticatedUserException() {
		super(ERR_MSG);
	}

}
