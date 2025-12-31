package com.fido.demo.util;

import com.fido.demo.controller.pojo.common.ServerPublicKeyCredential;
import com.fido.demo.controller.service.pojo.SessionBO;
import com.fido.demo.data.entity.CredentialEntity;
import com.fido.demo.data.redis.RedisService;
import com.fido.demo.data.repository.CredentialRepository;
import com.webauthn4j.WebAuthnAuthenticationManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class AuthenticationUtils {

    @Autowired
    RedisService redisService;

    @Autowired
    CredentialRepository credentialRepository;

    @Autowired
    private CredUtils credUtils;

    public boolean verifyAssertion(ServerPublicKeyCredential.Response response, String credentialId,
                                   ServerPublicKeyCredential.Extensions extensions) {
        List<CredentialEntity> credentialEntities = credentialRepository.findByExternalId(credentialId);
        CredentialEntity credential = credentialEntities.get(0);

        byte[] credentialIdBytea = credentialId.getBytes();
        byte[] userHandle = response.getUserHandle().getBytes();

        byte[] authenticatorData = Base64.getUrlDecoder().decode(response.getAuthenticatorData()); /* set attestationObject */
        byte[] clientDataJSON = Base64.getDecoder().decode(response.getClientDataJSON()); /* set clientDataJSON */;
        //String clientExtensionJSON = String.valueOf(extensions);  /* set clientExtensionJSON */;
        String clientExtensionJSON = null;
        try {
            clientExtensionJSON = extensions != null ? new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(extensions) : "{}";
        } catch (Exception e) {
            e.printStackTrace();
        }

        String sanitizedSignature = response.getSignature().replace("_", "/").replace('-', '+');
        while (sanitizedSignature.length() % 4 != 0) {
                sanitizedSignature += "=";
        }
        byte[] signature = null;
        try {
           signature = Base64.getDecoder().decode(sanitizedSignature);
        }catch (Exception e){
            System.out.println("Exception "+e.getMessage());
        }

        //Set<String> transports = CollectionUtils.isEmpty(clientResponse.getTransports()) ? null : new HashSet<String>(clientResponse.getTransports()); /* set transports: ToDO : handle empty transports */;

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
            credentialIdBytea, /* id of the credential*/
            userHandle,
            authenticatorData,
            clientDataJSON,
            clientExtensionJSON,
            signature
        );

        AuthenticationData authenticationData;
        WebAuthnAuthenticationManager webAuthnManager = new WebAuthnAuthenticationManager();

        try {
            authenticationData = webAuthnManager.parse(authenticationRequest);
        } catch (DataConversionException e) {
            throw new RuntimeException("Failed to parse authentication data", e);
        }

        // extract challenge from AuthenticationData
        String sessionKey = new String(
                Base64.getUrlEncoder()
                .withoutPadding()
                .encode(authenticationData.getCollectedClientData().getChallenge().getValue())
        );

        SessionBO sessionBO = (SessionBO) redisService.find(sessionKey);
        if(Objects.isNull(sessionBO)){
            throw new RuntimeException("Invalid Challenge");
        }

        Origin origin = Origin.create(sessionBO.getRp().getOrigin()) /* set origin */;
        String rpId = sessionBO.getRp().getId() /* set rpId */;
        Challenge challenge = new DefaultChallenge(sessionBO.getChallenge()); /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        CredentialRecord credentialRecord = credUtils.convertToWebAuthnRecord(credential);
        AuthenticationParameters authnParams = getAuthenticationParameters(credential, serverProperty, credentialRecord);

        AuthenticationData authnData = null;
        try {
               authnData = webAuthnManager.verify(authenticationData, authnParams);
        } catch (VerificationException e) {
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw new RuntimeException("Failed to validate authentication data", e);
        }

        return true;

    }

    private static AuthenticationParameters getAuthenticationParameters(CredentialEntity credential,
                                                                        ServerProperty serverProperty,
                                                                        CredentialRecord credentialRecord) {
        List<byte[]> allowCredentials = new ArrayList<>();
        //byte[] credId = credential.getExternalIdRaw().getBytes();
        byte[] credId = credential.getExternalId().getBytes();
        allowCredentials.add(credId);

        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;

        AuthenticationParameters authnParams = new AuthenticationParameters(
                serverProperty,
                credentialRecord,
                allowCredentials,
                userVerificationRequired,
                userPresenceRequired
        );
        return authnParams;
    }
}
