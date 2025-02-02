package com.fido.demo.controller.service;

import com.fido.demo.controller.pojo.authentication.AuthnOptions;
import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import com.fido.demo.controller.pojo.authentication.AuthnResponse;
import com.fido.demo.controller.pojo.common.RP;
import com.fido.demo.controller.pojo.common.User;
import com.fido.demo.controller.service.pojo.SessionBO;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.RelyingPartyEntity;
import com.fido.demo.data.entity.UserEntity;
import com.fido.demo.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service("authenticationService")
public class AuthenticationService extends BaseService {

    @Autowired
    private AuthenticationUtils authenticationUtils;

    public AuthnOptions getOptions(AuthnOptions request, String rpId){

        // fetch the user
        UserEntity userEntity = userRepository.findByUsername(request.getUsername());
        if(userEntity == null){
            throw new RuntimeException("User not found");
        }
        User user = User.builder()
                .name(userEntity.getUsername())
                .id(userEntity.getUserId())
                .displayName(userEntity.getDisplayName())
                .build();

        String relyingPartyId = rpId == null ? CommonConstants.DEFAULT_RP_ID : rpId;
        RelyingPartyEntity rpEntity = rpRepository.findByRpId(
                relyingPartyId);
        RP rp = RP.builder()
                .origin(rpEntity.getOrigin())
                .name(rpEntity.getName())
                .id(rpEntity.getRpId())
                .build();

        // fetch credentials
        List<CredentialEntity> allowedCredentials = credentialRepository.findByUsername(userEntity.getUsername());
        List<Map<String,String>> allowedCreds = allowedCredentials.stream()
                .map(item-> {
                    Map<String,String> map = new HashMap<>();
                    map.put("id", item.getExternalIdRaw());
                    map.put("type", "public-key");
                    return map;
                }).toList();

        // persist the session
        String challenge = cryptoUtil.getRandomBase64String();
        SessionBO sessionBO = SessionBO.builder()
                .challenge(challenge)
                .user(user)
                .rp(rp)
                .build();
        redisService.save(challenge, sessionBO);

        // build response
        AuthnOptions response = AuthnOptions.builder()
                .allowedCreds(allowedCreds)
                .rpId(CommonConstants.DEFAULT_RP_ID)
                .challenge(challenge)
                .timeout(CommonConstants.DEFAULT_TIMEOUT)
                .userVerification("true")
                .build();

        return response;
    }

    public AuthnResponse authenticate(AuthnRequest request, String rpId) {

        // verify the assertion: ToDO: too much crammed into single function, break it down
        boolean isVerified = authenticationUtils.verifyAssertion(request.getResponse(), request.getId());

        // construct webauthn mnager and verify the authentication
        if(isVerified) {
            // update the sign count
            System.out.println("Update the sign count");
        }
        return AuthnResponse.builder().build();
    }
}
