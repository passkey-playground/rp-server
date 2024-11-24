package com.fido.demo.controller.service;

import com.fido.demo.controller.pojo.authentication.AuthnOptions;
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
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
    private AuthenticationUtils authenticationUtils;

    public AuthnOptions getAuthNOptions(AuthnOptions request){

        // fetch RP
        RelyingPartyEntity rpEntity = rpRepository.findByRpId(request.getRpId());

        // fetch user
        byte[] userIdBytea = Base64.getDecoder().decode(request.getUserId());
        String userId = new String(userIdBytea, StandardCharsets.UTF_8);
        UserEntity userEntity = userRepository.findByUserId(userId);

        // save session (challenge, user, rp, sessionId)
        SessionState state = sessionUtils.getAuthnSession(request, rpEntity, userEntity);

        // fetch credentials for the user
        List<CredentialEntity> registeredCreds = credentialRepository.findByRpIdAndUserId(rpEntity.getId(), userEntity.getId());

        // build the response & return
        AuthnOptions response = credUtils.getAuthnOptionsResponse(registeredCreds, state);
        return response;
    }

    public AuthnResponse authenticate(AuthnRequest request) {
        // fetch the session State: ToDo if session not found, return 404 or 400
        SessionState session = sessionUtils.retrieveSession(request);

        // validate the challenge & signature sent by client using the registered public-key
        AuthenticationData authenticationData = authenticationUtils.validateAndGetAuthnData(request.getServerPublicKeyCredential(), session);

        // persist the credential with updates to sign_count and build the response object
        AuthnResponse authnResponse = authenticationUtils.updateCredentials(request.getServerPublicKeyCredential(), authenticationData, session);

        return authnResponse;
    }
}
