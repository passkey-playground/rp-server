package com.fido.demo.util;

import com.fido.demo.controller.pojo.authentication.AuthnOptions;
import com.fido.demo.controller.pojo.registration.RegRequest;
import com.fido.demo.controller.pojo.common.ServerPublicKeyCredential;
import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.AuthenticatorEntity;
import com.fido.demo.data.entity.CredentialConfigEntity;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.entity.CredentialEntityOld;
import com.fido.demo.data.repository.CredentialRepository;
import com.fido.demo.util.serde.WebAuthn4JSerDe;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static com.fido.demo.util.CommonConstants.*;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class CredUtils {

    @Autowired
    JSONUtils jsonUtils;

    @Autowired
    CredentialRepository credentialRepository;

    @Autowired
    WebAuthn4JSerDe webAuthn4JSerDe;


    /* --------------------------------- Registration Uitls (start)--------------------------------*/




    /* --------------------------------- Registration Uitls (end) --------------------------------*/

    // persist the WebAuthn4J CredentialRecordImpl
    public CredentialEntity persistCredRecord(CredentialRecordImpl credentialRecord,
                                              RegistrationData registrationData,
                                              String credentialId,
                                              String credentialRawId,
                                              String username){
        /**
         * credential record has 4 main objects
         * 1) attestationobject
         * 2) collectedClientData
         * 3) clientExtensions
         * 4) transports
         */

        /* Attestation Object 1) authenticator data & 2) attestation statement */
        AttestationObject attestationObject = registrationData.getAttestationObject();
        byte[] authenticatorDataBytea = webAuthn4JSerDe.serialize(attestationObject.getAuthenticatorData());
        byte[] attStmtBytea = webAuthn4JSerDe.serialize(credentialRecord.getAttestationStatement());

        /* collectedClientData */
        byte[] clientData = webAuthn4JSerDe.serialize(credentialRecord.getClientData());


        /* client extensions */
        //eg: webAuthn4JSerDe.serialize(credentialRecord.getClientExtensions())

        /* transports */
        Set<AuthenticatorTransport> transportSet = credentialRecord.getTransports();
        String transports = webAuthn4JSerDe.serialize(transportSet);

        /**
         * 3 columns
         * - authenticator_data
         * - attestation_statement
         * - client extensions
         * - collected clientData
         * - transports
         */
        CredentialEntity credentialEntity = CredentialEntity.builder()
                .username(username)
                .externalId(credentialId)
                .externalIdRaw(credentialRawId)
                .authenticatorData(authenticatorDataBytea)
                .attestationStatement(attStmtBytea)
                .collectedClientData(clientData)
                .transports(transports)
                .build();

        CredentialEntity ret = credentialRepository.save(credentialEntity);
        return ret;
    }

    /* --------------------------------- Authentication Uitls (start)  --------------------------------*/
    // ToDO : change the cred argument to list
    public AuthnOptions getAuthnOptionsResponse(List<CredentialEntityOld> registeredCreds, SessionState state){

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

        AuthnOptions response = AuthnOptions.builder()
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

    /* --------------------------------- Authentication Uitls (end)  --------------------------------*/

    /* --------------------------------- Common Uitls (start) --------------------------------*/

    public CredentialEntityOld getCredentialEntity(RegRequest request, SessionState session, RegistrationData registrationData) {
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

        CredentialEntityOld credentialEntity = CredentialEntityOld.builder()
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

    public CredentialRecord convertToWebAuthnRecord(CredentialEntity credential) {

        /**
         *
         * Credential record:
         *  - attestationobject
         *  - collected client data
         *  - transports
         *  - extensions
         *
         *  AttestationObject
         *  - authenticator data
         *  - attestation statement
         *
         */

        byte[] attestationStmtBytea = credential.getAttestationStatement();
        byte[] authenticatorDataBytea = credential.getAuthenticatorData();
        byte[] collectedClientDataBytea = credential.getCollectedClientData();


        AttestationStatement attestationStatement = webAuthn4JSerDe.deSerAttStmt(attestationStmtBytea);
        AuthenticatorData authenticatorData = webAuthn4JSerDe.deSerAuthenticatorData(authenticatorDataBytea);

        AttestationObject attestationObject = new AttestationObject(authenticatorData, attestationStatement);

        CollectedClientData collectedClientData = webAuthn4JSerDe.deSerCollectedClientData(collectedClientDataBytea);

        AuthenticatorTransport internalTransport = AuthenticatorTransport.create("internal");
        Set<AuthenticatorTransport> transports = new HashSet<>();
        transports.add(internalTransport);

        //
        CredentialRecordImpl credentialRecord = new CredentialRecordImpl(
                attestationObject,
                collectedClientData,
                null,
                transports
        );
        return credentialRecord;
    }

    /* --------------------------------- Common Uitls --------------------------------*/
}
