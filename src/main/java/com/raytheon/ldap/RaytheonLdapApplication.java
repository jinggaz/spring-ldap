package com.raytheon.ldap;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

//import io.swagger.v3.oas.annotations.OpenAPIDefinition;
//import io.swagger.v3.oas.annotations.info.Info;

@SpringBootApplication
//@OpenAPIDefinition(info = @Info(title = "Raytheon LDAP Demo"))
public class RaytheonLdapApplication {

	public static void main(String[] args) {
		SpringApplication.run(RaytheonLdapApplication.class, args);
	}

}
