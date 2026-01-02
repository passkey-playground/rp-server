package com.fido.demo.util.serde;

import com.fido.demo.util.AttestationStatementEnvelope;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class WebAuthn4JSerDe {

    /**
     *
     * Credential record
     * -> attestationObject
     * -> collectedClientData
     * -> clientExtensions
     * -> transports
     */


     /**
     * Attestation object contains 2 objects
     * 1) authenticator data
     * 2) attestation statement
     *
     */

    // <------------------------------ AttestationObject (start)-------------------------------------------------->
    public byte[] serialize(AttestationObject attestationObject){

        // attestation statement
        AttestationStatement statement = attestationObject.getAttestationStatement();
        byte[] attStmtSer = this.serialize(statement);

        // authenticatorData
        AuthenticatorData authenticatorData = attestationObject.getAuthenticatorData();
        byte[] authenticatorDataSer = this.serialize(authenticatorData);

        return authenticatorDataSer;
    }

    // <------------------------------ AttestationObject (end)-------------------------------------------------->

    public byte[] serialize(AuthenticatorData authenticatorData){
        /**
         * Authenticator data contains:
         * -> rpIdHash
         * -> flags
         * -> counter
         * -> authenticatorCredentialData
         */

        ObjectConverter objectConverter = new ObjectConverter();
        AuthenticatorDataConverter converter = new AuthenticatorDataConverter(objectConverter);
        byte[] ret = converter.convert(authenticatorData);
        return ret;
    }

    public AuthenticatorData deSerAuthenticatorData(byte[] data){
        /**
         * Authenticator data contains:
         * -> rpIdHash
         * -> flags
         * -> counter
         * -> authenticatorCredentialData
         */

        ObjectConverter objectConverter = new ObjectConverter();
        AuthenticatorDataConverter converter = new AuthenticatorDataConverter(objectConverter);
        AuthenticatorData ret = converter.convert(data);
        return ret;
    }




    // <------------------------------ AttestedCredentialData (start)-------------------------------------------------->
    public byte[] serialize(AttestedCredentialData data){

        ObjectConverter converter = new ObjectConverter();
        AttestedCredentialDataConverter attestedCredentialDataConverter =
                new AttestedCredentialDataConverter(converter);

        // serialize
        byte[] ret = attestedCredentialDataConverter.convert(data);
        return ret;
    }

    public AttestedCredentialData deSerAttestedCredentialData(byte[] data){

        ObjectConverter converter = new ObjectConverter();
        AttestedCredentialDataConverter attestedCredentialDataConverter =
                new AttestedCredentialDataConverter(converter);

        // serialize
        AttestedCredentialData ret = attestedCredentialDataConverter.convert(data);
        return ret;
    }
    // <------------------------------ AttestedCredentialData (start)-------------------------------------------------->

    // <------------------------------ AttestationStatement (start)-------------------------------------------------->
    public byte[] serialize(AttestationStatement statement){

        ObjectConverter converter = new ObjectConverter();

        //serialize
        AttestationStatementEnvelope envelope = new AttestationStatementEnvelope(statement);
        byte[] serializedEnvelope = converter.getCborConverter().writeValueAsBytes(envelope);
        return serializedEnvelope;

    }

    public AttestationStatement deSerAttStmt(byte[] data){

        ObjectConverter converter = new ObjectConverter();

        //deserialize
        AttestationStatementEnvelope deserializedEnvelope = converter.getCborConverter().readValue(data,
                AttestationStatementEnvelope.class);
        AttestationStatement attestationStatement = deserializedEnvelope.getAttestationStatement();
        return  attestationStatement;


    }
    // <------------------------------ AttestationStatement (end)-------------------------------------------------->



    // <------------------------------ CollectedClientData (start)-------------------------------------------------->
    public byte[] serialize(CollectedClientData clientData){
        ObjectConverter converter = new ObjectConverter();
        CollectedClientDataConverter collectedClientDataConverter =
                new CollectedClientDataConverter(converter);

        byte[] ret = collectedClientDataConverter.convertToBytes(clientData);
        return ret;
    }

    public CollectedClientData deSerCollectedClientData(byte[] src){
        ObjectConverter converter = new ObjectConverter();
        CollectedClientDataConverter collectedClientDataConverter =
                new CollectedClientDataConverter(converter);

        CollectedClientData ret = collectedClientDataConverter.convert(src);
        return ret;
    }

    //<------------------------------ CollectedClientData (end)-------------------------------------------------->

    // <------------------------------ clientExtensions (start)-------------------------------------------------->

    // <------------------------------ clientExtensions (end)-------------------------------------------------->


    // <------------------------------ transports (end)-------------------------------------------------->
    public String serialize(Set<AuthenticatorTransport> transports){
        ObjectConverter converter = new ObjectConverter();
        String serializedTransports = converter.getJsonConverter().writeValueAsString(transports);
        return  serializedTransports;
    }

    public Set<AuthenticatorTransport> deSerTransports(String input){
        ObjectConverter converter = new ObjectConverter();
        Set<AuthenticatorTransport> transports = converter.getJsonConverter().readValue(input, Set.class);
        return  transports;
    }
    // <------------------------------ transports (end)-------------------------------------------------->

}

