package com.fido.demo.controller.service;

import com.fido.demo.controller.pojo.common.ServerPublicKeyCredential;
import com.fido.demo.controller.pojo.common.User;
import com.fido.demo.controller.pojo.registration.RegOptionsRequest;
import com.fido.demo.controller.pojo.registration.RegistrationResponse;
import com.fido.demo.controller.pojo.registration.RegOptionsResponse;
import com.fido.demo.controller.pojo.registration.RegistrationRequest;
import com.fido.demo.controller.service.pojo.CermonyBO;
import com.fido.demo.controller.service.pojo.SessionBO;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.util.*;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.RegistrationData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service("registrationService")
public class RegistrationService extends BaseService {

    @Autowired
    Registrationutils registrationutils;

    public RegOptionsResponse getOptions(RegOptionsRequest request, String rpId){

        /**
         * 1) create user
         * 2) fetch RP and its configs
         * 3) build the cermony configs
         * 4) persist state
         * 5) build and return response
         */

        User user = userUtils.getUser(request.getUserName(), request.getDisplayName());

        List<Map<String,String>> credentials = userUtils.getUserCredentials(request.getUserName()) == null ? new ArrayList<>() : userUtils.getUserCredentials(request.getUserName());

        CermonyBO cermonyBO = rpUtils.getCermonyConfigs(rpId, request);

        String challenge = cryptoUtil.getRandomBase64String();// challenge

        // save the state for subsequent calls
        SessionBO state = sessionUtils.persistAttestationState(user, challenge, cermonyBO);


        // response
        RegOptionsResponse response = RegOptionsResponse.builder()
                /*  Mandatory fields (start) */
                .rp(cermonyBO.getRp())                                                   /* relying party*/
                .user(user)                                               /* user  */
                .challenge(challenge)                                     /* challenge */
                .pubKeyCredParams(cermonyBO.getPubKeyCredPams())                        /* pubKeyCredParams */
                /*  Mandatory fields (end) */
                //.authenticatorSelection(cermonyBO.getAuthenticatorSelection())            /* authenticator selection */
                .authenticatorSelection(request.getAuthenticatorSelection())
                .attestation(request.getAttestation())
                //.attestation(cermonyBO.getAttestation())                                  /* attestation */
                .timeout(cermonyBO.getTimeout())                                          /* timeout */
                .excludeCredentials(credentials)                     /* excludeCredentials : ToDo - fetch deactivated or deleted creds for the user and set here */
                .extensions(request.getExtensions())                                   /* extensions */
                //.sessionId(sessionId)                                    /* sessionId */
                .build();

        return  response;
    }

    public RegistrationResponse register(RegistrationRequest request, String rpId){

        // Question: is rpID needed ? it is already cached in the session
        ServerPublicKeyCredential.Response registrationResponse = request.getResponse();

        /**
         * 1) parse the response
         * 2) retrieve the session
         * 3) verify the public key & create a credential record
         * 4) serialize and persist credential record & user
         */

        // 1) parse the response
        RegistrationData registrationData = registrationutils.parseAttestation(
                /* attestation object: fmt, authData, attStmt */
                registrationResponse.getAttestationObject(),
                /* client data json: type, challenge, origin, cross-origin, token-bidning*/
                registrationResponse.getClientDataJSON()
        );

        // 2) retrieve the session
        String challenge = new String(
                Base64.getUrlEncoder()
                .withoutPadding()
                .encode(registrationData.getCollectedClientData().getChallenge().getValue())
        );
        SessionBO sessionBO = (SessionBO) redisService.find(challenge);
        if(Objects.isNull(sessionBO)){
            throw new RuntimeException("Invalid Challenge");
        }

        // 2) retrieve the session & 3) verify the public key
        CredentialRecordImpl credentialRecord  = registrationutils
                .verifyAttestation(registrationData, sessionBO);

        // 4) serialize and persist: user & credential records
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

}
