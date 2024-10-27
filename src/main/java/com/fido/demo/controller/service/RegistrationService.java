package com.fido.demo.controller.service;

import com.fido.demo.controller.pojo.PubKeyCredParam;
import com.fido.demo.controller.pojo.registration.RegRequest;
import com.fido.demo.controller.pojo.registration.options.AuthenticatorSelection;
import com.fido.demo.controller.pojo.registration.options.RegOptions;
import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.AuthenticatorEntity;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.RelyingPartyEntity;
import com.fido.demo.data.entity.UserEntity;
import com.fido.demo.data.redis.RedisService;
import com.fido.demo.data.repository.AuthenticatorRepository;
import com.fido.demo.data.repository.CredentialRepository;
import com.fido.demo.data.repository.RPRepository;
import com.fido.demo.data.repository.UserRepository;
import com.fido.demo.util.*;
import com.webauthn4j.data.RegistrationData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.rest.webmvc.ResourceNotFoundException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static com.fido.demo.util.CommonConstants.SESSION_ID_DEFAULT_LENGTH;
import static com.fido.demo.util.CommonConstants.CHALLENGE_DEFAULT_LENGTH;


@Service("registrationService")
public class RegistrationService {

    @Autowired
    Registrationutils registrationutils;

    @Autowired
    private RedisService redisService;

    @Autowired
    RPRepository rpRepository;

    @Autowired
    CredentialRepository credRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    AuthenticatorRepository authenticatorRepository;

    @Autowired
    private RpUtils rpUtils;

    @Autowired
    private CredUtils credUtils;

    @Autowired
    CryptoUtil cryptoUtil;

    public RegOptions getRegOptions(RegOptions request){
        //session_id : secure random string
        String sessionId = cryptoUtil.generateSecureRandomString(SESSION_ID_DEFAULT_LENGTH);

        RelyingPartyEntity rpEntity = rpRepository.findByRpId(request.getRp().getId());
        if(rpEntity == null){ //ToDo: Move all the validations to validators
            throw new ResourceNotFoundException("RP not found");
        }

        byte[] userIdBytea =Base64.getDecoder().decode(request.getUser().getId());
        String userId = new String(userIdBytea, StandardCharsets.UTF_8);
        UserEntity userEntity = userRepository.findByUserId(userId);

        //ToDo: dont return the value configured for RP, match it with rp values or fail if config and incoming value mismatch
        AuthenticatorSelection authenticatorSelection = rpUtils.getAuthenticatorSelection(rpEntity.getConfigs());
        String attestation = rpUtils.getAttestation(rpEntity.getConfigs());

        List<PubKeyCredParam> pubKeyCredParam = rpUtils.getPubKeyCredParam(rpEntity.getConfigs());
        long timeout = rpUtils.getTimeout(rpEntity.getConfigs());

        String challenge = cryptoUtil.generateSecureRandomString(CHALLENGE_DEFAULT_LENGTH);// challenge
        String challengeBase64 = Base64.getEncoder().encodeToString(challenge.getBytes());
        SessionState state = SessionState.builder() // ToDo : instead of saving the incoming data without validation, validate and persist
                .sessionId(sessionId)
                .rp(request.getRp())
                .rpDbId(rpEntity.getId())
                .challenge(challengeBase64)
                .user(request.getUser())
                .userDbId(userEntity.getId())
                .authenticatorSelection(request.getAuthenticatorSelection())
                .timeout(timeout)
                .build();

        redisService.save(sessionId, state); // save the state for subsequent calls

        RegOptions response = RegOptions.builder() // build the response
                .rp(request.getRp())                                                   /* relying party*/
                .user(request.getUser())                                               /* user (ToDo : Validate the user) */
                .authenticatorSelection(authenticatorSelection)                        /* authenticator selection */
                .attestation(attestation)                                              /* attestation */
                .challenge(challengeBase64)                                            /* challenge */
                .pubKeyCredParams(pubKeyCredParam)                                     /* pubKeyCredParams */
                .timeout(timeout)                                                      /* timeout */
                .excludeCredentials(new ArrayList<>())                                 /* excludeCredentials : ToDo - parse from Db and set the value */
                .sessionId(sessionId)                                                  /* sessionId */
                .build();

        return  response;
    }

    public RegRequest getReg(RegRequest request){
        // fetch the session State
        SessionState session = (SessionState) redisService.find(request.getSessionId());

        // validate session and extract registrationData
        RegistrationData registrationData = registrationutils.validateAndGetRegData(request.getServerPublicKeyCredential(), session);

        // save the creds: ToDO: authenticator is saved twice if a new key/pair is generated address the unique ness
        CredentialEntity savedCreds = registrationutils.saveCredentials(request, session, registrationData);

        // construct the response and return
        RegRequest response = registrationutils.getRegistrationResponse(savedCreds, session);

        return response;
    }

}


// Sample incoming request
/*
{
  "rp" : {
    "name" : "Test RP",
    "icon" : null,
    "id" : "localhost"
  },
  "user" : {
    "name" : "TestUser",
    "icon" : null,
    "id" : "65fUCTlqPlOSk22tkrkJ2m8I2MEhpF4fCI_pdosMAzk",
    "displayName" : "Test Display Name"
  },
  "authenticatorSelection": {
    "requireResidentKey": true,
    "userVerification": "preferred",
    "authenticatorAttachment": "platform"
  },
  "attestation": "none",
  "credProtect" : null
}
*/


// Sample response
/*
{
  "serverResponse" : {
    "description" : null,
    "internalError" : "SUCCESS",
    "internalErrorCode" : 0,
    "internalErrorCodeDescription" : null
  },
  "rp" : {
    "name" : "example1",
    "icon" : null,
    "id" : "localhost"
  },
  "user" : {
    "name" : "TestUser",
    "icon" : null,
    "id" : "65fUCTlqPlOSk22tkrkJ2m8I2MEhpF4fCI_pdosMAzk",
    "displayName" : "Test Display Name"
  },
  "challenge" : "4uxOYNYRZ0a-WPuh24Uki0kNrM5_ioDPVNgaCfy2szLzc0QaVamxa66Y7v8bAyxUGiqU7O8mXP36R_oyWaVDpg",
  "pubKeyCredParams" : [ {
    "type" : "public-key",
    "alg" : -65535
  }, {
    "type" : "public-key",
    "alg" : -257
  }, {
    "type" : "public-key",
    "alg" : -258
  }, {
    "type" : "public-key",
    "alg" : -259
  }, {
    "type" : "public-key",
    "alg" : -37
  }, {
    "type" : "public-key",
    "alg" : -38
  }, {
    "type" : "public-key",
    "alg" : -39
  }, {
    "type" : "public-key",
    "alg" : -7
  }, {
    "type" : "public-key",
    "alg" : -35
  }, {
    "type" : "public-key",
    "alg" : -36
  }, {
    "type" : "public-key",
    "alg" : -8
  }, {
    "type" : "public-key",
    "alg" : -43
  } ],
  "timeout" : 180000,
  "excludeCredentials" : [ ],
  "authenticatorSelection" : {
    "authenticatorAttachment" : "platform",
    "requireResidentKey" : true,
    "userVerification" : "preferred"
  },
  "attestation" : "none",
  "sessionId" : "d9adf5d0-e819-42de-ac35-defa241f1b6c",
  "extensions" : {
    "credProps" : true
  }
}
*/