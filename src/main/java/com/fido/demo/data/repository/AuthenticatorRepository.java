package com.fido.demo.data.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.fido.demo.data.entity.AuthenticatorEntity;

@Repository
public interface AuthenticatorRepository extends JpaRepository<AuthenticatorEntity, Integer>{

}
