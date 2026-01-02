package com.fido.demo.util;

import com.fido.demo.controller.pojo.common.User;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.UserEntity;
import com.fido.demo.data.repository.CredentialRepository;
import com.fido.demo.data.repository.UserRepository;
import com.webauthn4j.data.RegistrationData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class UserUtils {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    CryptoUtil cryptoUtil;

    @Autowired
    CredentialRepository credentialRepository;

    public User getUser(String username, String displayName){

        String userId = cryptoUtil.getRandomBase64String(20);;
        return User.builder()
                .id(userId)
                .name(username)
                .displayName(displayName)
                .build();
    }

    public List<Map<String,String>> getUserCredentials(String username){
        // fetch the user
        UserEntity userEntity = userRepository.findByUsername(username);
        if(userEntity == null){
            return null;
        }
        List<CredentialEntity> userCredentials = credentialRepository.findByUsername(userEntity.getUsername());

        List<Map<String,String>> creds = userCredentials.stream()
                .map(item-> {
                    Map<String,String> map = new HashMap<>();
                    map.put("id", item.getExternalIdRaw());
                    map.put("type", "public-key");
                    return map;
                }).toList();
        return creds;
    }


}
