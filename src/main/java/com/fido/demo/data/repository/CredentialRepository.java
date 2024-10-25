package com.fido.demo.data.repository;

import com.fido.demo.data.entity.CredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.math.BigInteger;

@Repository
public interface CredentialRepository extends JpaRepository<CredentialEntity, BigInteger> {
    //List<CredentialEntity> findById(BigInteger id);
    List<CredentialEntity> findByUserId(BigInteger userId);
    List<CredentialEntity> findByRpIdAndUserId(BigInteger rpId, BigInteger userId);
    List<CredentialEntity>  findByAuthenticatorCredentialId(byte[] authenticatorCredentialId);
}
