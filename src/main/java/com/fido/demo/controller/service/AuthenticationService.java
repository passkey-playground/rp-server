package com.fido.demo.controller.service;

import com.fido.demo.controller.pojo.authentication.AuthnOptions;
import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import com.fido.demo.controller.pojo.authentication.AuthnResponse;
import com.fido.demo.controller.pojo.common.RP;
import com.fido.demo.controller.pojo.common.User;
import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.CredentialEntityOld;
import com.fido.demo.data.entity.RelyingPartyEntity;
import com.fido.demo.data.entity.UserEntity;
import com.fido.demo.data.redis.RedisService;
import com.fido.demo.data.repository.CredentialRepository;
import com.fido.demo.data.repository.RPRepository;
import com.fido.demo.data.repository.UserRepository;
import com.fido.demo.util.*;
import com.webauthn4j.data.AuthenticationData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service("authenticationService")
public class AuthenticationService {
    @Autowired
    CredentialRepository credentialRepository;

    @Autowired
    RPRepository rpRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    SessionUtils sessionUtils;

    @Autowired
    CredUtils credUtils;

    @Autowired
    private AuthenticationUtils authenticationUtils;
    @Autowired
    private CryptoUtil cryptoUtil;
    @Autowired
    private RedisService redisService;

    public AuthnOptions getAuthNOptions(AuthnOptions request){

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

        RelyingPartyEntity rpEntity = rpRepository.findByRpId(CommonConstants.DEFAULT_RP_ID);
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
        SessionState sessionState = SessionState.builder()
                .challenge(challenge)
                .user(user)
                .rp(rp)
                .build();
        redisService.save(challenge, sessionState);


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

    public AuthnResponse authenticate(AuthnRequest request) {

        // fetch credentials
        boolean isVerified = authenticationUtils.verifyAssertion(request.getResponse(), request.getId());


        // construct webauthn mnager and verify the authentication




        return null;
//        // fetch the session State: ToDo if session not found, return 404 or 400
//        SessionState session = sessionUtils.retrieveSession(request);
//
//        // validate the challenge & signature sent by client using the registered public-key
//        AuthenticationData authenticationData = authenticationUtils.validateAndGetAuthnData(request.getServerPublicKeyCredential(), session);
//
//        // persist the credential with updates to sign_count and build the response object
//        AuthnResponse authnResponse = authenticationUtils.updateCredentials(request.getServerPublicKeyCredential(), authenticationData, session);
//
//        return authnResponse;
    }
}
