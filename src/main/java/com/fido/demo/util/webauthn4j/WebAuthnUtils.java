package com.fido.demo.util.webauthn4j;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
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
import com.webauthn4j.verifier.attestation.statement.tpm.NullTPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.NullFIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.CertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.DefaultCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessVerifier;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.Arrays;

@Component
public class WebAuthnUtils {

    private WebAuthnRegistrationManager registrationManager;

    @PostConstruct
    void postConstruct(){
        //registrationManager = WebAuthnRegistrationManager.createNonStrictWebAuthnRegistrationManager();

        ObjectConverter objectConverter = new ObjectConverter();
        File metadataBLOBFile = new File("src/main/resources/blob.jwt");
        MetadataBLOBProvider blobProvider = new LocalFileMetadataBLOBProvider(objectConverter, metadataBLOBFile.toPath());
        TrustAnchorRepository trustAnchorRepository = new MetadataBLOBBasedTrustAnchorRepository(blobProvider);
        CertPathTrustworthinessVerifier trustworthinessVerifier = new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository);
        registrationManager = new WebAuthnRegistrationManager(
                Arrays.asList(
                        new NoneAttestationStatementVerifier(),
                        new NullFIDOU2FAttestationStatementVerifier(),
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
        return registrationManager.verify(data, parameters);
    }
}
