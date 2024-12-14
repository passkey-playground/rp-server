package com.fido.demo.util;

import com.fido.demo.controller.pojo.common.User;
import com.fido.demo.controller.pojo.common.ServerPublicKeyCredential;
import com.fido.demo.controller.pojo.common.AuthenticatorSelection;
import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.*;
import com.fido.demo.data.redis.RedisService;
import com.fido.demo.data.repository.AuthenticatorRepository;
import com.fido.demo.data.repository.CredentialRepository;
import com.fido.demo.data.repository.UserRepository;
import com.fido.demo.util.webauthn4j.WebAuthnUtils;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class Registrationutils {

    @Autowired
    CredentialRepository credentialRepository;

    @Autowired
    AuthenticatorRepository authenticatorRepository;

    @Autowired
    CredUtils credUtils;

    @Autowired
    Base64Utils base64Utils;

    @Autowired
    private RedisService redisService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    JSONUtils jsonUtils;

    @Autowired
    WebAuthnUtils webAuthnUtils;

    public RegistrationData parseRegistrationData(String attestationObject,
                                                  String clientDataJSON){
        //ToDO: Create a "request" scoped or "thread safe" bean and init it there


        byte[] attestationBytea = base64Utils.decodeURLAsBytes(attestationObject);
        byte[] clientDataBytea = base64Utils.decodeURLAsBytes(clientDataJSON);

        String clientExtensionJSON = null;  /* set clientExtensionJSON */
        Set<String> transports = new HashSet<String>(); /* ToDo: set transports from response*/


        RegistrationRequest registrationRequest = new RegistrationRequest(attestationBytea, clientDataBytea,
                clientExtensionJSON, transports);

        RegistrationData registrationData = null;
        try{
            registrationData = webAuthnUtils.parse(registrationRequest);
        }
        catch (DataConversionException e){
            throw new RuntimeException("Exception while parsing registration data", e);
        }

        return  registrationData;
    }

    public CredentialRecordImpl verifyRegistrationData(RegistrationData registrationData,
                                                       SessionState sessionState){


        CollectedClientData clientData = registrationData.getCollectedClientData();
        if(Objects.isNull(clientData)){
            throw new RuntimeException("ClientData is null/empty");
        }

        // retrieve the session

        Origin origin = Origin.create(sessionState.getRp().getOrigin()) /* set origin */;
        String rpId = sessionState.getRp().getId() /* set rpId */;
        Challenge originalChallenge = new DefaultChallenge(sessionState.getChallenge()); /* set challenge */
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, originalChallenge, tokenBindingId);

        // expectations
        boolean userVerificationRequired = false;
        boolean userPresenceRequired = true;

        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                userVerificationRequired,
                userPresenceRequired);

        RegistrationData ret = null;
        try {
            ret = webAuthnUtils.verify(registrationData, registrationParameters);
        }
        catch (VerificationException e){
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw new RuntimeException("Exception while verifying registration data", e);
        }

        CredentialRecordImpl credentialRecord = new CredentialRecordImpl(
                ret.getAttestationObject(),
                ret.getCollectedClientData(),
                ret.getClientExtensions(),
                ret.getTransports()
        );

        return credentialRecord;
    }
    
    public User saveUser(RegistrationData registrationData){
        CollectedClientData clientData = registrationData.getCollectedClientData();
        if(Objects.isNull(clientData)){
            throw new RuntimeException("ClientData is null/empty");
        }

        // retrieve the session
        String challenge = new String(Base64.getUrlEncoder().withoutPadding().encode(registrationData.getCollectedClientData().getChallenge().getValue()));
        SessionState sessionState = redisService.find(challenge);

        User user = sessionState.getUser();
        UserEntity userEntity = UserEntity.builder()
                .userId(user.getId())
                .displayName(user.getDisplayName())
                .username(user.getName())
                .build();

        UserEntity exisintUser = userRepository.findByUsername(user.getName());
        if(exisintUser == null){
            userRepository.save(userEntity);
        }else {
            System.out.println("Not persisting the data");
        }

        return user;
    }

}
