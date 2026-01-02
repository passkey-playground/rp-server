package com.fido.demo.data.repository;

import com.fido.demo.data.entity.RPConfigEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.math.BigInteger;
import java.util.List;

@Repository
public interface RPConfigRepository extends JpaRepository<RPConfigEntity, BigInteger> {
    List<RPConfigEntity> findByRelyingPartyId(BigInteger rpId);
}
