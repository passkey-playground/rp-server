package com.fido.demo.util;

import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import com.fido.demo.controller.pojo.authentication.AuthnResponse;
import com.fido.demo.controller.pojo.registration.ServerPublicKeyCredential;
import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.AuthenticatorEntity;
import com.fido.demo.data.entity.CredentialConfigEntity;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.repository.CredentialRepository;
import com.webauthn4j.WebAuthnAuthenticationManager;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.AuthenticatorTransportConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.verifier.exception.VerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.rest.webmvc.ResourceNotFoundException;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.fido.demo.util.CommonConstants.*;

@Component
public class AuthenticationUtils {

    @Autowired
    CredentialRepository credentialRepository;



    public AuthenticationData validateAndGetAuthnData(ServerPublicKeyCredential publicKeyCredential, SessionState sessionState){

        ServerPublicKeyCredential.Response clientResponse = publicKeyCredential.getResponse();

        // client properties
        byte[] credentialId = publicKeyCredential.getId().getBytes();
        byte[] userHandle = publicKeyCredential.getResponse().getUserHandle().getBytes();

        byte[] authenticatorData = Base64.getUrlDecoder().decode(clientResponse.getAuthenticatorData()); /* set attestationObject */
        byte[] clientDataJSON = Base64.getDecoder().decode(clientResponse.getClientDataJSON()); /* set clientDataJSON */;
        String clientExtensionJSON = null;  /* set clientExtensionJSON */;
        byte[] signature = Base64.getDecoder().decode(clientResponse.getSignature());
        //Set<String> transports = CollectionUtils.isEmpty(clientResponse.getTransports()) ? null : new HashSet<String>(clientResponse.getTransports()); /* set transports: ToDO : handle empty transports */;

        // Server properties
        Origin origin = Origin.create(sessionState.getRp().getOrigin()) /* set origin */;
        String rpId = sessionState.getRp().getId() /* set rpId */;
        Challenge challenge = new DefaultChallenge(sessionState.getChallenge()); /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        List<byte[]> allowCredentials = null;
        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                credentialId, /* id of the credential*/
                userHandle,
                authenticatorData,
                clientDataJSON,
                clientExtensionJSON,
                signature
        );

        CredentialRecord credentialRecord = this.getWebAuthn4jCredentialRecord(publicKeyCredential, sessionState);
        AuthenticationParameters authnParams = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                allowCredentials,
                userVerificationRequired,
                userPresenceRequired
        );

        AuthenticationData authenticationData;
        WebAuthnAuthenticationManager webAuthnManager = new WebAuthnAuthenticationManager();

        try {
            authenticationData = webAuthnManager.parse(authenticationRequest);
        } catch (DataConversionException e) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw new RuntimeException("Failed to parse authentication data", e);
        }

        AuthenticationData authnData = null;
        try {
               authnData = webAuthnManager.verify(authenticationData, authnParams);
        } catch (VerificationException e) {
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw new RuntimeException("Failed to validate authentication data", e);
        }

        return authnData;

    }

    public AuthnResponse updateCredentials(ServerPublicKeyCredential publicKeyCredential, AuthenticationData authenticationData, SessionState sessionState){

        CredentialEntity credentialEntity = this.updateAuthenticatorData(publicKeyCredential, authenticationData);

        AuthenticatorEntity authenticatorEntity = credentialEntity.getAuthenticator();

        AuthnResponse authnResponse = AuthnResponse.builder()
                .aaguid(authenticatorEntity.getAaguid().toString())
                .userId(sessionState.getUser().getId())
                .userPresent(authenticationData.getAuthenticatorData().isFlagUP())
                .userVerified(authenticationData.getAuthenticatorData().isFlagUV())
                .build();

        return authnResponse;
    }

    // method to update AuthenticatorDat
    private CredentialEntity updateAuthenticatorData(ServerPublicKeyCredential credential, AuthenticationData authenticationData){
        // ToDO : break Authentication data elements and only update sign_count, rest of the elements doesn't change

        // we need to update the sign count so the next time validation succeds
        AuthenticatorData authenticatiorData = authenticationData.getAuthenticatorData();

        long signCount = authenticatiorData.getSignCount();

        byte[] credIdBytea = credential.getId().getBytes();

        CredentialEntity credEntity = credentialRepository.findByAuthenticatorCredentialId(credIdBytea).get(0);
        credEntity.setSign_count(signCount);

        credentialRepository.save(credEntity);

        return  credEntity;
    }
    private CredentialRecord getWebAuthn4jCredentialRecord(ServerPublicKeyCredential publicKeyCredential, SessionState sessionState){
        List<CredentialEntity> savedCred = credentialRepository.findByRpIdAndUserId(sessionState.getRpDbId(), sessionState.getUserDbId());
        // filter if the incoming cred id is present
        CredentialEntity credentialEntity = savedCred.stream().filter(item -> {
            String id = new String(item.getAuthenticatorCredentialId());
            return id.compareTo(publicKeyCredential.getId()) == 0;
        }).findFirst().orElseGet(null);

        if(credentialEntity == null){
            throw new ResourceNotFoundException("Credential not found");
        }


        ObjectConverter objectConverter = new ObjectConverter();

        /*attestation object*/
        CredentialConfigEntity attestationStatement = credentialEntity.getConfigs().stream().filter(item -> item.getSettingKey().compareTo(ATTESTATION_STATEMENT_KEY) == 0).findFirst().orElse(null);
        String serializedEnvelope = attestationStatement.getSettingValue();
        AttestationStatementEnvelope deserializedEnvelope = objectConverter.getCborConverter().readValue(Base64UrlUtil.decode(serializedEnvelope), AttestationStatementEnvelope.class);
        AttestationStatement statement = deserializedEnvelope.getAttestationStatement();

        CredentialConfigEntity authenticatorDataConfig = credentialEntity.getConfigs().stream().filter(item -> item.getSettingKey().compareTo(AUTHENTICATOR_DATA) == 0).findFirst().orElse(null);
        String serializedAuthenticatorData = authenticatorDataConfig.getSettingValue();
        AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        AuthenticatorData authenticatorData = authenticatorDataConverter.convert(Base64UrlUtil.decode(serializedAuthenticatorData));


        // new AuthenticatorData
        AuthenticatorData webAuthNAuthenticatorData = new AuthenticatorData(
                authenticatorData.getRpIdHash(),
                authenticatorData.getFlags(),
                credentialEntity.getSign_count(),
                authenticatorData.getAttestedCredentialData()
        );

        AttestationObject attestationObject = new AttestationObject(webAuthNAuthenticatorData, statement);

        /* collectedClientData */
        CredentialConfigEntity collectedClientDataConfig = credentialEntity.getConfigs().stream().filter(item -> item.getSettingKey().compareTo(COLLECTED_CLIENT_DATA) == 0).findFirst().orElse(null);
        String collectedClientDataString = collectedClientDataConfig.getSettingValue();
        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);
        CollectedClientData collectedClientData = converter.convert(Base64UrlUtil.decode(collectedClientDataString));


        CredentialConfigEntity transportsConfig = credentialEntity.getConfigs().stream().filter(item -> item.getSettingKey().compareTo(AUTHENTICATOR_TRANSPORTS) == 0).findFirst().orElse(null);
        String transportsString = transportsConfig.getSettingValue();
        String [] transporString = transportsString.split(",");
        Set<AuthenticatorTransport> transports = new HashSet<>();
        AuthenticatorTransportConverter transportConverter = new AuthenticatorTransportConverter();
        for(String item : transporString){
            AuthenticatorTransport t = transportConverter.convert(item);
            transports.add(t);
        }

        CredentialRecord credentialRecord = new CredentialRecordImpl(
                attestationObject,/*attestationObject*/
                collectedClientData, /*collectedClientData*/
                null,/*clientExtensions*/
                transports /*transports*/
                 );
        return credentialRecord;
    }

}
