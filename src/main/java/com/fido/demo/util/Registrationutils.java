package com.fido.demo.util;

import com.fido.demo.controller.pojo.registration.RegRequest;
import com.fido.demo.controller.pojo.registration.ServerPublicKeyCredential;
import com.fido.demo.controller.pojo.registration.options.AuthenticatorSelection;
import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.AuthenticatorEntity;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.RelyingPartyConfigEntity;
import com.fido.demo.data.repository.AuthenticatorRepository;
import com.fido.demo.data.repository.CredentialRepository;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.*;

@Component
public class Registrationutils {

    @Autowired
    CredentialRepository credentialRepository;

    @Autowired
    AuthenticatorRepository authenticatorRepository;

    @Autowired
    CredUtils credUtils;

    public RegistrationData validateAndGetRegData(ServerPublicKeyCredential publicKeyCredential, SessionState sessionState){

        WebAuthnRegistrationManager webAuthnManager = WebAuthnRegistrationManager.createNonStrictWebAuthnRegistrationManager();
        ServerPublicKeyCredential.Response clientResponse = publicKeyCredential.getResponse();

        // client properties
        byte[] attestationObject = Base64.getUrlDecoder().decode(clientResponse.getAttestationObject()); /* set attestationObject */
        byte[] clientDataJSON = Base64.getDecoder().decode(clientResponse.getClientDataJSON()); /* set clientDataJSON */;
        String clientExtensionJSON = null;  /* set clientExtensionJSON */;
        Set<String> transports = new HashSet<String>(clientResponse.getTransports()); /* set transports */;

        // Server properties
        Origin origin = Origin.create(sessionState.getRp().getOrigin()) /* set origin */;
        String rpId = sessionState.getRp().getId() /* set rpId */;
        Challenge challenge = new DefaultChallenge(sessionState.getChallenge()); /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        boolean userVerificationRequired = false;
        boolean userPresenceRequired = true;

        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON, clientExtensionJSON, transports);
        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, userVerificationRequired, userPresenceRequired);

        RegistrationData registrationData;
        try{
            registrationData = webAuthnManager.parse(registrationRequest);
        }
        catch (DataConversionException e){
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }

        try{
            webAuthnManager.verify(registrationData, registrationParameters);
        }
        catch (VerificationException e){
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e;
        }

        return registrationData;

    }

    public CredentialEntity saveCredentials(RegRequest request, SessionState session, RegistrationData registrationData){

        CredentialEntity credentialEntity = credUtils.getCredentialEntity(request, session, registrationData);
        AuthenticatorEntity authenticatorEntity = credUtils.getAuthenticatorEntity(request, registrationData);

        AuthenticatorEntity savedAuthnEntity = authenticatorRepository.save(authenticatorEntity);
        credentialEntity.setAuthenticator(savedAuthnEntity);

        // persist the credentials
        CredentialEntity savedCreds = credentialRepository.save(credentialEntity);

        return  savedCreds;
    }


    // credentials are persisted, build "registration" response
    public RegRequest getRegistrationResponse(CredentialEntity credEntity){
        // aaguid
        UUID aaguid = credEntity.getAuthenticator().getAaguid();
        // credentialId
        String credentialId = new String(credEntity.getAuthenticatorCredentialId());

        //attestationType
        String attestationType = credEntity.getAttestationFormat();

        // authenticatorTransports
        String authenticatorTransports = StringUtils.collectionToDelimitedString(credEntity.getAuthenticator().getTransports(), ",");

        //userVerified: ToDo: update this code
        boolean userVerified = true;

        //residentKey present or not: ToDO : update this code
        boolean rk = true;

        RegRequest ret = RegRequest.builder()
                .aaguid(aaguid.toString())
                .credentialId(credentialId)
                .attestationType(attestationType)
                .authenticatorTransports(new ArrayList<String>(){{
                    add(authenticatorTransports);
                }})
                .userVerified(userVerified)
                .rk(rk)
                .build();

        return ret;

    }

    public AuthenticatorSelection getAuthenticatorSelection(List<RelyingPartyConfigEntity> rpConfigs){
        /*
        * setting_name
        * require_user_verification
        * authenticator_attachment
        * require_resident_key
        * */
        RelyingPartyConfigEntity userVerificationConfig = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals("require_user_verification"))
                                                    .findFirst().orElse(null);

        RelyingPartyConfigEntity requireResidentKey = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals("require_resident_key"))
                                                    .findFirst().orElse(null);

        RelyingPartyConfigEntity authenticatorAttachment = rpConfigs.stream()
                                                    .filter(rpConfig -> rpConfig.getSettingKey().equals("authenticator_attachment"))
                                                    .findFirst().orElse(null);

        AuthenticatorSelection authenticatorSelection = new AuthenticatorSelection();
        authenticatorSelection.setUserVerification(userVerificationConfig == null ? "preferred" : userVerificationConfig.getSettingValue()); // ToDo : move to constants
        authenticatorSelection.setRequireResidentKey(requireResidentKey == null ? false : Boolean.valueOf(requireResidentKey.getSettingValue()));
        authenticatorSelection.setAuthenticatorAttachment(authenticatorAttachment == null ? "platform" : authenticatorAttachment.getSettingValue()); // ToDo : reconsider the default value and move to constants

        return authenticatorSelection;
    }

}
