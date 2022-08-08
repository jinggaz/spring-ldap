package com.raytheon.ldap.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.raytheon.ldap.auth.LdapTokenUtil;
import com.raytheon.ldap.auth.LdapUser;
import com.raytheon.ldap.dto.LoginForm;
import com.raytheon.ldap.dto.ResultForm;

@RestController
@RequestMapping("/users")
public class UserController {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private LdapTokenUtil ldapTokenUtil;

	@PostMapping("/login")
	public ResponseEntity<ResultForm> login(@RequestBody LoginForm loginForm) throws Exception {
		final String email = loginForm.getEmail();
		final String password = loginForm.getPassword();

		final Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(email, password));

		LdapUser user = (LdapUser) authentication.getPrincipal();
		final String token = ldapTokenUtil.create(user.getEmail());
			
		return ResponseEntity.ok(new ResultForm(token));
	}

	@GetMapping("/test")
	public ResponseEntity<String> test() {
		return ResponseEntity.ok("Hello World!\n Test endpoint is protected by Spring Security.");
	}

}
