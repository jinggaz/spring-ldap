package com.raytheon.ldap.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.raytheon.ldap.auth.LdapUser;
import com.raytheon.ldap.dto.LoginForm;
import com.raytheon.ldap.dto.RefreshTokenRequest;
import com.raytheon.ldap.dto.ResultForm;
import com.raytheon.ldap.service.RefreshTokenService;
import com.raytheon.ldap.service.UserService;

@RestController
@RequestMapping("/users")
public class UserController {

	@Autowired
	private UserService userServie;

	@Autowired
	private RefreshTokenService refreshTokenService;

	@PostMapping("/login")
	public ResponseEntity<ResultForm> login(@RequestBody LoginForm loginForm) throws Exception {

		final ResultForm resultForm = userServie.login(loginForm);

		return ResponseEntity.ok(resultForm);
	}

	@GetMapping("/user/{email}")
	public ResponseEntity<LdapUser> userDetail(@PathVariable String email) {

		final LdapUser ldapUser = (LdapUser) userServie.loadUserByEmail(email);

		return ResponseEntity.ok(ldapUser);
	}

	@GetMapping("/test")
	public ResponseEntity<String> test(@RequestHeader(value = "refresh_token", required = false) String refreshToken) {
		return ResponseEntity.ok("Hello World!\n Test endpoint is protected by Spring Security.");
	}

	@PostMapping("/refreshtoken")
	public ResponseEntity<ResultForm> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {

		final ResultForm resultForm = refreshTokenService.refreshToken(refreshTokenRequest.getRefreshToken());

		return ResponseEntity.ok(resultForm);
	}

}
