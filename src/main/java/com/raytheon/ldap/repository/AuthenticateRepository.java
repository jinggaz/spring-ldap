package com.raytheon.ldap.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.raytheon.ldap.entity.AuthenticateEntity;

public interface AuthenticateRepository extends CrudRepository<AuthenticateEntity, Long> {
	
	Optional<AuthenticateEntity> findByRefreshToken(String refreshToken);
	
}
