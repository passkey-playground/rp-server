package com.fido.demo.util.webauthn4j;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.metadata.FidoMDS3MetadataBLOBProvider;
import com.webauthn4j.metadata.LocalFileMetadataBLOBProvider;
import com.webauthn4j.metadata.MetadataBLOBBasedMetadataStatementRepository;
import com.webauthn4j.metadata.MetadataBLOBProvider;
import com.webauthn4j.metadata.anchor.MetadataBLOBBasedTrustAnchorRepository;
import com.webauthn4j.verifier.attestation.statement.androidkey.NullAndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.apple.NullAppleAnonymousAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.NullPackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.NullTPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.NullFIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.SelfAttestationTrustworthinessVerifier;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.Arrays;

@Component
public class WebAuthnUtils {

    private WebAuthnRegistrationManager registrationManager;

    private WebAuthnRegistrationManager fullRegistrationManager;

    @PostConstruct
    void postConstruct(){
        //registrationManager = WebAuthnRegistrationManager.createNonStrictWebAuthnRegistrationManager();
        registrationManager = new WebAuthnRegistrationManager(
                Arrays.asList(
                        new NoneAttestationStatementVerifier(),
                        new NullFIDOU2FAttestationStatementVerifier(),
                        new PackedAttestationStatementVerifier(),
                        //new NullPackedAttestationStatementVerifier(),
                        new NullTPMAttestationStatementVerifier(),
                        new NullAndroidKeyAttestationStatementVerifier(),
                        new NullAndroidSafetyNetAttestationStatementVerifier(),
                        new NullAppleAnonymousAttestationStatementVerifier()
                ),
                //trustworthinessVerifier,
                new NullCertPathTrustworthinessVerifier(),
                new NullSelfAttestationTrustworthinessVerifier()
        );

        ObjectConverter objectConverter = new ObjectConverter();
        File metadataBLOBFile = new File("src/main/resources/blob.jwt");
        MetadataBLOBProvider blobProvider = new LocalFileMetadataBLOBProvider(objectConverter, metadataBLOBFile.toPath());
        TrustAnchorRepository trustAnchorRepository = new MetadataBLOBBasedTrustAnchorRepository(blobProvider);
        CertPathTrustworthinessVerifier trustworthinessVerifier = new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository);


        fullRegistrationManager =new WebAuthnRegistrationManager(
                Arrays.asList(
                        new NoneAttestationStatementVerifier(),
                        new NullFIDOU2FAttestationStatementVerifier(),
                        //new PackedAttestationStatementVerifier(),
                        new NullPackedAttestationStatementVerifier(),
                        new NullTPMAttestationStatementVerifier(),
                        new NullAndroidKeyAttestationStatementVerifier(),
                        new NullAndroidSafetyNetAttestationStatementVerifier(),
                        new NullAppleAnonymousAttestationStatementVerifier()
                ),
                trustworthinessVerifier,
                //new NullCertPathTrustworthinessVerifier(),
                new NullSelfAttestationTrustworthinessVerifier()
        );

    }

    public RegistrationData parse(RegistrationRequest request){
        return registrationManager.parse(request);
    }

    public RegistrationData verify(RegistrationData data, RegistrationParameters parameters){
        AttestationObject attestationObject = data.getAttestationObject();
        AttestationStatement attStmt = attestationObject.getAttestationStatement();

        // Check the attestation format is "packed"
        if ("packed".equals(attestationObject.getFormat())) {

            PackedAttestationStatement packedStmt = (PackedAttestationStatement) attStmt;

            if (packedStmt.getX5c() != null && !packedStmt.getX5c().isEmpty()) {
                // FULL attestation (has certificate chain)
                System.out.println("FULL packed attestation detected");
                return fullRegistrationManager.verify(data, parameters);
                // You can add custom validation or logging here
            } else {
                // SELF attestation (no x5c present)
                System.out.println("SELF packed attestation detected");
                // Optionally allow or deny based on your policy
            }

        }
        return registrationManager.verify(data, parameters);
    }
}
