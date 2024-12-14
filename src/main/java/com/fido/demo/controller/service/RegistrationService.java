package com.fido.demo.controller.service;

import com.fido.demo.controller.pojo.PubKeyCredParam;
import com.fido.demo.controller.pojo.common.RP;
import com.fido.demo.controller.pojo.common.ServerPublicKeyCredential;
import com.fido.demo.controller.pojo.common.User;
import com.fido.demo.controller.pojo.registration.RegOptionsRequest;
import com.fido.demo.controller.pojo.registration.RegistrationResponse;
import com.fido.demo.controller.pojo.common.AuthenticatorSelection;
import com.fido.demo.controller.pojo.registration.RegOptionsResponse;
import com.fido.demo.controller.pojo.registration.RegistrationRequest;
import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.RelyingPartyEntity;
import com.fido.demo.data.redis.RedisService;
import com.fido.demo.data.repository.AuthenticatorRepository;
import com.fido.demo.data.repository.CredentialRepository;
import com.fido.demo.data.repository.RPRepository;
import com.fido.demo.data.repository.UserRepository;
import com.fido.demo.util.*;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.RegistrationData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.rest.webmvc.ResourceNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;


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
    CryptoUtil cryptoUtil;

    @Autowired
    Base64Utils base64Utils;

    @Autowired
    UserUtils userUtils;

    @Autowired
    private CredUtils credUtils;


    public RegOptionsResponse getRegOptions(RegOptionsRequest request){
        //ToDo: Move all the validations to validators

        //NOTE: FIDO conformane tests doesn't have RP_ID in the request, default to an RP
        RelyingPartyEntity rpEntity = rpRepository.findByRpId(CommonConstants.DEFAULT_RP_ID);
        if(rpEntity == null){
            throw new ResourceNotFoundException("RP not found");
        }
        RP rp = RP.builder()
                .id(rpEntity.getRpId())
                .name(rpEntity.getName())
                .origin(rpEntity.getOrigin())
                .build();

        //ToDo: Should the user exist in Db "yes/no"? for now error out if "no"
        User user = userUtils.getUser(request.getUserName(), request.getDisplayName());

        //ToDo: dont return the value configured for RP,
        //match it with rp values or fail if config and incoming value mismatch
        AuthenticatorSelection authenticatorSelection = rpUtils.getAuthenticatorSelection(rpEntity.getConfigs());
        String attestation = rpUtils.getAttestation(rpEntity.getConfigs());

        List<PubKeyCredParam> pubKeyCredParam = rpUtils.getPubKeyCredParam(rpEntity.getConfigs());
        long timeout = rpUtils.getTimeout(rpEntity.getConfigs());
        String challenge = cryptoUtil.getRandomBase64String();// challenge
        //String challenge = cryptoUtil.getRandmString();

        // save the state for subsequent calls
        SessionState state = SessionState.builder()
                .sessionId(challenge) // use challenge as session key
                .challenge(challenge)
                .rpId(rp.getId())
                .rp(rp)
                .user(user)
                .authenticatorSelection(request.getAuthenticatorSelection())
                .timeout(timeout)
                .build();
        redisService.save(challenge, state);

        // response
        RegOptionsResponse response = RegOptionsResponse.builder()
                /*  Mandatory fields (start) */
                .rp(rp)                                                   /* relying party*/
                .user(user)                                               /* user  */
                .challenge(challenge)                                     /* challenge */
                .pubKeyCredParams(pubKeyCredParam)                        /* pubKeyCredParams */
                /*  Mandatory fields (end) */
                .authenticatorSelection(authenticatorSelection)            /* authenticator selection */
                .attestation(attestation)                                  /* attestation */
                .timeout(timeout)                                          /* timeout */
                .excludeCredentials(new ArrayList<>())                     /* excludeCredentials : ToDo - fetch deactivated or deleted creds for the user and set here */
                //.sessionId(sessionId)                                    /* sessionId */
                .build();

        return  response;
    }

    public RegistrationResponse createRegistration(RegistrationRequest request){

        ServerPublicKeyCredential.Response registrationResponse = request.getResponse();

        /**
         * 1) parse the response
         * 2) retrieve the session
         * 3) verify the public key & create a credential record
         * 4) serialize and persist credential record & user
         */

        // 1) parse the response
        RegistrationData registrationData = registrationutils.parseRegistrationData(
                registrationResponse.getAttestationObject(),
                registrationResponse.getClientDataJSON()
        );

        // 2) retrieve the session
        String challenge = new String(
                Base64.getUrlEncoder()
                .withoutPadding()
                .encode(registrationData.getCollectedClientData().getChallenge().getValue())
        );
        SessionState sessionState = (SessionState) redisService.find(challenge);
        if(Objects.isNull(sessionState)){
            throw new RuntimeException("Invalid Challenge");
        }

        // 2) retrieve the session & 3) verify the public key
        CredentialRecordImpl credentialRecord  = registrationutils
                .verifyRegistrationData(registrationData, sessionState);

        // 4) serialize and persist credential record
        User user = registrationutils.saveUser(registrationData);
        CredentialEntity credentialEntity = credUtils.persistCredRecord(
                credentialRecord,
                registrationData,
                request.getId(),
                request.getRawId(),
                user.getName());

        // construct the response and return
        RegistrationResponse response = RegistrationResponse.builder().build();
        return response;
    }

    public RegOptionsResponse getRegOptions(RegOptionsResponse request){
        //session_id : secure random string
        String sessionId = cryptoUtil.getRandomBase64String();

        RelyingPartyEntity rpEntity = rpRepository.findByRpId(request.getRp().getId());
        if(rpEntity == null){ //ToDo: Move all the validations to validators
            throw new ResourceNotFoundException("RP not found");
        }

        //ToDo: dont return the value configured for RP, match it with rp values or fail if config and incoming value mismatch
        AuthenticatorSelection authenticatorSelection = rpUtils.getAuthenticatorSelection(rpEntity.getConfigs());
        String attestation = rpUtils.getAttestation(rpEntity.getConfigs());

        List<PubKeyCredParam> pubKeyCredParam = rpUtils.getPubKeyCredParam(rpEntity.getConfigs());
        long timeout = rpUtils.getTimeout(rpEntity.getConfigs());

        String challenge = cryptoUtil.getRandomBase64String();// challenge
        String challengeBase64 = Base64.getEncoder().encodeToString(challenge.getBytes());
        SessionState state = SessionState.builder() // ToDo : instead of saving the incoming data without validation, validate and persist
                .sessionId(sessionId)
                .rp(request.getRp())
                .challenge(challengeBase64)
                .user(request.getUser())
                .authenticatorSelection(request.getAuthenticatorSelection())
                .timeout(timeout)
                .build();

        redisService.save(sessionId, state); // save the state for subsequent calls

        RegOptionsResponse response = RegOptionsResponse.builder() // build the response
                /*  Mandatory fields (start) */
                .rp(request.getRp())                                                   /* relying party*/
                .user(request.getUser())                                               /* user  */
                .challenge(challengeBase64)                                            /* challenge */
                .pubKeyCredParams(pubKeyCredParam)                                     /* pubKeyCredParams */
                /*  Mandatory fields (end) */
                .authenticatorSelection(authenticatorSelection)                        /* authenticator selection */
                .attestation(attestation)                                              /* attestation */
                .timeout(timeout)                                                      /* timeout */
                .excludeCredentials(new ArrayList<>())                                 /* excludeCredentials : ToDo - fetch deactivated or deleted creds for the user and set here */
                .sessionId(sessionId)                                                  /* sessionId */
                .build();

        return  response;
    }
}
