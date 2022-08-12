package com.raytheon.ldap.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.raytheon.ldap.dto.LoginForm;
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

	@GetMapping("/test")
	public ResponseEntity<String> test() {
		return ResponseEntity.ok("Hello World!\n Test endpoint is protected by Spring Security.");
	}

	@PostMapping("/refreshtoken")
	public ResponseEntity<ResultForm> refreshToken(@RequestHeader(value="refresh_token")String refreshToken) {

		final ResultForm resultForm = refreshTokenService.refreshToken(refreshToken);

		return ResponseEntity.ok(resultForm);

	}
}
