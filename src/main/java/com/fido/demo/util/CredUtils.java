package com.fido.demo.util;

import com.fasterxml.jackson.databind.util.JSONPObject;
import com.fido.demo.controller.pojo.authentication.AuthenticationOptionsResponse;
import com.fido.demo.controller.pojo.registration.RegRequest;
import com.fido.demo.controller.pojo.registration.RegResponse;
import com.fido.demo.controller.pojo.registration.ServerPublicKeyCredential;
import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.AuthenticatorConfigEntity;
import com.fido.demo.data.entity.CredentialConfigEntity;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.AuthenticatorEntity;
import com.fido.demo.data.repository.CredentialRepository;
import com.webauthn4j.WebAuthnAuthenticationManager;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.AuthenticatorTransportConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.challenge.DefaultChallenge;

import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.verifier.exception.VerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.rest.webmvc.ResourceNotFoundException;
import org.springframework.stereotype.Component;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.converter.exception.DataConversionException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.Map;
import java.util.UUID;

import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

@Component
public class CredUtils {

    public static final String ATTESTED_CREDENTIAL_DATA = "attested_credential_data";
    public static final String ATTESTED_CREDENTIAL_DATA_KEY = "attested_credential_data";
    public static final String ATTESTATION_STATEMENT_KEY = "attestation_statement";
    public static final String RP_ID_HASH = "rp_id_hash";
    public static final String AUTHENTICATOR_DATA = "AUTHENTICATOR_DATA";
    private static final String COLLECTED_CLIENT_DATA = "COLLECTED_CLIENT_DATA";
    public static final String AUTHENTICATOR_TRANSPORTS = "AUTHENTICATOR_TRANSPORTS";
    @Autowired
    JSONUtils jsonUtils;

    @Autowired
    CredentialRepository credentialRepository;


    /* --------------------------------- Registration Uitls (start)--------------------------------*/

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

    /* --------------------------------- Registration Uitls (end) --------------------------------*/


    /* --------------------------------- Authentication Uitls (start)  --------------------------------*/
    // ToDO : change the cred argument to list
    public AuthenticationOptionsResponse getAuthnOptionsResponse(List<CredentialEntity> registeredCreds, SessionState state){

        // challenge
        String challenge = state.getChallenge();

        // timeout
        long timeout = state.getTimeout();

        //rpId
        String rpId = state.getRp().getId();

        // userVerification : ToDO change it to read from state
        String userVerification = "preferred";

        // sessionid
        String sessionId = state.getSessionId();

        List<Map<String,String>> allowedCreds =registeredCreds.stream().map( (item) -> {
            Map<String, String> entry = new HashMap<String, String>();
            entry.put("type", "public-key");
            entry.put("id", new String(item.getAuthenticatorCredentialId()));
            return entry;
        }).collect(Collectors.toList());

        AuthenticationOptionsResponse response = AuthenticationOptionsResponse.builder()
        .challenge(challenge)
        .timeout(timeout)
        .rpId(rpId)
        .allowedCreds(allowedCreds)
        .userVerification(userVerification)
        //.isUserVerification(userVerification)
        .sessionId(sessionId)
        .build();

        return response;
    }

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

        AttestationObject attestationObject = new AttestationObject(authenticatorData, statement);

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


    /* --------------------------------- Authentication Uitls (end)  --------------------------------*/



    /* --------------------------------- Common Uitls (start) --------------------------------*/

    public CredentialEntity getCredentialEntity(RegRequest request, SessionState session, RegistrationData registrationData) {
        // id, user_id, rp_id, public_key(UUID), sign_count, transports, attestation_format, authenticator_credential_id
        //id is auto generated

        // rp_id : note this is Db id
        BigInteger rpId = session.getRpDbId();

        // user_id
        BigInteger userId = session.getUserDbId();

        // public_key
        byte[] publicKey = this.getPubKey(request).getBytes();

        // signCount
        long signCount = this.getSignCount(registrationData);

        // ToDo : for now only attestation_none cases are handled => below hard coded value
        String attestationFormat = "none";

        // authenticator_credential_id
        byte[] authneticatorCredentialId = request.getServerPublicKeyCredential().getId().getBytes();

        List<CredentialConfigEntity> configs = this.getCredentialConfigs(session, registrationData);

        CredentialEntity credentialEntity = CredentialEntity.builder()
                .rpId(rpId)                                                      /* Column : rp_id */
                .userId(userId)                                                  /* Column : user_id */
                .publicKey(publicKey)                                            /* Column : public_key */
                .sign_count(signCount)                                           /* Column : sign_count */
                .attestationFormat(attestationFormat)                            /* Column : attestation_format */
                .authenticatorCredentialId(authneticatorCredentialId)            /* Column : authenticator_credential_id */
                .configs(configs)                                                /* Child : credential configs */
                .build();

        return  credentialEntity;
    }

    //ToDo : currently only attestation_data is stored, function is too specific. refactor this ********** High Priority ************************
    private List<CredentialConfigEntity> getCredentialConfigs(SessionState session, RegistrationData registrationData){

        // store attestationObject and attestationStatement as strings
        ObjectConverter objectConverter = new ObjectConverter();

        // attested credential data
        AttestedCredentialDataConverter attestedCredentialDataConverter
                = new AttestedCredentialDataConverter(objectConverter);
        byte[] attestedCredData = attestedCredentialDataConverter.convert(registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData());
        String attCredData = Base64UrlUtil.encodeToString(attestedCredData);

        CredentialConfigEntity attestedCredDataConfig = this.buildCredConfigEntity(ATTESTED_CREDENTIAL_DATA, attCredData);
        List<CredentialConfigEntity> ret = new ArrayList<>();
        ret.add(attestedCredDataConfig);

        //attestatoin statement
        AttestationStatement attestationStatement = registrationData.getAttestationObject().getAttestationStatement();
        if(attestationStatement != null){
            AttestationStatementEnvelope envelope = new AttestationStatementEnvelope(attestationStatement);
            byte[] serializedEnvelope = objectConverter.getCborConverter().writeValueAsBytes(envelope);
            String statement = Base64UrlUtil.encodeToString(serializedEnvelope);

            CredentialConfigEntity attestationStatementConfig = this.buildCredConfigEntity(ATTESTATION_STATEMENT_KEY, statement);
            ret.add(attestationStatementConfig);
        }

        AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        byte[] authenticatarDataBytea = authenticatorDataConverter.convert(registrationData.getAttestationObject().getAuthenticatorData());
        String authenticatorData = Base64UrlUtil.encodeToString(authenticatarDataBytea);

        CredentialConfigEntity authenticatorDataConfig = this.buildCredConfigEntity(AUTHENTICATOR_DATA, authenticatorData);
        ret.add(authenticatorDataConfig);

        byte[] collectedClientDataBytea = registrationData.getCollectedClientDataBytes();
        if(collectedClientDataBytea != null && collectedClientDataBytea.length > 0){
            String collectedClientData = Base64UrlUtil.encodeToString(collectedClientDataBytea);
            CredentialConfigEntity collectedClientDataConfig = this.buildCredConfigEntity(COLLECTED_CLIENT_DATA, collectedClientData);
            ret.add(collectedClientDataConfig);
        }

        String transports = registrationData.getTransports().stream().map(item -> item.getValue()).collect(Collectors.joining(","));
        CredentialConfigEntity transportsConfig = this.buildCredConfigEntity(AUTHENTICATOR_TRANSPORTS, transports);
        ret.add(transportsConfig);
        // ToDO : handle clientextensions and transports

        // rpIdhash
        String rpIdHash = Base64UrlUtil.encodeToString(registrationData.getAttestationObject().getAuthenticatorData().getRpIdHash());
        CredentialConfigEntity rpIdHashConfig = this.buildCredConfigEntity(RP_ID_HASH, rpIdHash);
        ret.add(rpIdHashConfig);

        return ret;
    }

    private CredentialConfigEntity buildCredConfigEntity(String settingKey, String settingValue){
        CredentialConfigEntity configEntity = CredentialConfigEntity.builder()
                .settingKey(settingKey)
                .settingValue(settingValue)
                .build();

        return configEntity;
    }

    private long getSignCount(RegistrationData registrationData) {
        long signCount = registrationData.getAttestationObject().getAuthenticatorData().getSignCount(); //ToDo : use null checks, regData is returned by WebAuthn4J lib so might not need null checks
        return  signCount;
    }

    private String getPubKey(RegRequest request) {
        ServerPublicKeyCredential serverPublicKeyCredential = request.getServerPublicKeyCredential();
        String publicKey = serverPublicKeyCredential.getResponse().getPublicKey();
        return publicKey;
    }

    private String getTransports(RegRequest request){
        ServerPublicKeyCredential serverPublicKeyCredential = request.getServerPublicKeyCredential();
        List<String> transports = serverPublicKeyCredential.getResponse().getTransports();
        return String.join(",", transports);
    }

    public AuthenticatorEntity getAuthenticatorEntity(RegRequest request, RegistrationData registrationData){
        // transports
        List<String> transports = registrationData.getTransports().stream().map(transport -> transport.getValue()).collect(Collectors.toList()); // ToDo : handle multiple transports
        AAGUID aauid = registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid();

        AuthenticatorEntity authenticatorEntity = AuthenticatorEntity.builder()
                .aaguid(aauid.getValue())
                .transports(transports)
                .build();

        return authenticatorEntity;

    }

    /* --------------------------------- Common Uitls --------------------------------*/
}
