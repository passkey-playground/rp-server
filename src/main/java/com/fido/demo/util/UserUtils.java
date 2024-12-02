package com.fido.demo.util;

import com.fido.demo.controller.pojo.common.User;
import com.fido.demo.data.repository.UserRepository;
import com.webauthn4j.data.RegistrationData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UserUtils {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    CryptoUtil cryptoUtil;

    public User getUser(String username, String displayName){

        String userId = cryptoUtil.getRandomBase64String(20);;
        return User.builder()
                .id(userId)
                .name(username)
                .displayName(displayName)
                .build();
    }
}
