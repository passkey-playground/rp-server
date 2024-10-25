package com.fido.demo.controller.service;

import com.fido.demo.controller.pojo.authentication.AuthenticationOptionsRequest;
import com.fido.demo.controller.pojo.authentication.AuthenticationOptionsResponse;
import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import com.fido.demo.controller.pojo.authentication.AuthnResponse;
import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.RelyingPartyEntity;
import com.fido.demo.data.entity.UserEntity;
import com.fido.demo.data.redis.RedisService;
import com.fido.demo.data.repository.CredentialRepository;
import com.fido.demo.data.repository.RPRepository;
import com.fido.demo.data.repository.UserRepository;
import com.fido.demo.util.AuthenticationUtils;
import com.fido.demo.util.CredUtils;
import com.fido.demo.util.SessionUtils;
import com.webauthn4j.data.AuthenticationData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

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
    private RedisService redisService;

    @Autowired
    private AuthenticationUtils authenticationUtils;

    public AuthenticationOptionsResponse getAuthNOptions(AuthenticationOptionsRequest request){

        // fetch RP
        RelyingPartyEntity rpEntity = rpRepository.findByRpId(request.getRpId());

        // fetch user
        UserEntity userEntity = userRepository.findByUserId(request.getUserId());

        // save session (challenge, user, rp, sessionId)
        SessionState state = sessionUtils.getAutnSession(request, rpEntity, userEntity);

        // fetch credentials for the user
        List<CredentialEntity> registeredCreds = credentialRepository.findByRpIdAndUserId(rpEntity.getId(), userEntity.getId());

        // build the response & return
        AuthenticationOptionsResponse response = credUtils.getAuthnOptionsResponse(registeredCreds, state);
        return response;
    }

    public AuthnResponse authenticate(AuthnRequest request) {
        // fetch the session State: ToDo if session not found, return 404 or 400
        SessionState session = (SessionState) redisService.find(request.getSessionId());

        // validate the challenge & signature sent by client using the registered public-key
        AuthenticationData authenticationData = authenticationUtils.validateAndGetAuthnData(request.getServerPublicKeyCredential(), session);

        // persist the credential with updates to sign_count and build the response object
        AuthnResponse authnResponse = authenticationUtils.updateCredentials(request.getServerPublicKeyCredential(), authenticationData, session);

        return authnResponse;
    }
}
