package com.fido.demo.data.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "CREDENTIALS2")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialEntity {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "cred_sequence_generator")
    @SequenceGenerator(name = "cred_sequence_generator", sequenceName = "credentials_id_seq", allocationSize = 1)
    private BigInteger id;

    @Column(name = "username", nullable = false)
    private String username;

    @Column(name = "user_id")
    private BigInteger userId;

    @Column(name = "rp_id")
    private BigInteger rpId;

    @Column(name = "external_id")
    private String externalId;

    @Column(name = "external_id_raw")
    private String externalIdRaw;


    @Column(name = "authenticator_data")
    private byte[] authenticatorData;

    @Column(name = "attestation_statement")
    private byte[] attestationStatement;

    @Column(name = "client_extensions")
    private byte[] clientExtensions;

    @Column(name = "collected_client_data")
    private byte[] collectedClientData;

    @Column(name = "transports")
    private String transports;

    @JoinColumn(name = "credential_id")
    @OneToMany(fetch = FetchType.LAZY)
    private List<CredentialConfigEntity> configs;

    @JoinColumn(name = "credential_id")
    @OneToOne(fetch = FetchType.LAZY)
    private AuthenticatorEntity authenticator;

    @Column(name = "created_at")
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;

}
