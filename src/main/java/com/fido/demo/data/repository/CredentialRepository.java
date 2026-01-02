package com.fido.demo.data.repository;

import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.CredentialEntityOld;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.math.BigInteger;

@Repository
public interface CredentialRepository extends JpaRepository<CredentialEntity, Integer> {
    CredentialEntity findById(int id);
    CredentialEntity findByUserId(int userId);
    CredentialEntity findByRpAndUserId(int rpId, int userId);
}
