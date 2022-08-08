package com.raytheon.ldap.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.raytheon.ldap.auth.LdapAuthenticationProvider;
import com.raytheon.ldap.auth.LdapTokenFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private LdapAuthenticationProvider ldapAuthenticationProvider;
	
	@Autowired
	private LdapTokenFilter ldapTokenFilter;
	
	private static final String[] AUTH_WHITELIST = { 
			"/authenticate",
			"/swagger-resources/**",
			"/swagger-ui/**",
			"/v3/api-docs",
			"/webjars/**" };

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		auth.authenticationProvider(ldapAuthenticationProvider);
		
		auth.ldapAuthentication()
		.userDnPatterns("uid={0},ou=people")
		.groupSearchBase("ou=groups")
		.contextSource()
			.url("ldap://localhost:8389/dc=springframework,dc=org")
		.and()
		.passwordCompare().passwordEncoder(new BCryptPasswordEncoder()).passwordAttribute("userPassword");
	}

	@Override
	public void configure(WebSecurity webSecurity) throws Exception {
		webSecurity.ignoring().antMatchers(AUTH_WHITELIST);
	}

	public void configure(HttpSecurity httpSecurity) throws Exception {
  
		  httpSecurity
		  	.csrf().disable()
		  	.authorizeRequests()
		  	.antMatchers("users/login").permitAll()
		  	.antMatchers(HttpMethod.GET, "/users/test").hasRole("PEOPLE")
		  	.and()
		  	.sessionManagement()
		  	.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		  	.and()
		  	.addFilterBefore(ldapTokenFilter,  UsernamePasswordAuthenticationFilter.class)
		  	.formLogin().disable();
	  }

}
