package com.fido.demo.data.repository;

import org.springframework.stereotype.Repository;
import com.fido.demo.data.entity.UserEntity;

import java.math.BigInteger;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;



@Repository
public interface UserRepository extends JpaRepository<UserEntity, BigInteger>{
    //UserEntity findById(BigInteger id);
    UserEntity findByUserId(String userId);
    UserEntity findByUsername(String username);
}
