package com.fido.demo.data.repository;


import com.fido.demo.data.entity.RelyingPartyEntity;

import java.math.BigInteger;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RPRepository extends JpaRepository<RelyingPartyEntity, BigInteger> {
    // Additional query methods can be defined here
    //RelyingPartyEntity findById(BigInteger id);
    RelyingPartyEntity findByRpId(String rpId);
}
