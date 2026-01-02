package com.fido.demo.data.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.List;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

@Entity
@Table(name = "CREDENTIALS")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialEntityOld {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "cred_sequence_generator")
    @SequenceGenerator(name = "cred_sequence_generator", sequenceName = "credentials_id_seq", allocationSize = 1)
    private BigInteger id;

    @Column(name = "user_id")
    private BigInteger userId;

    @Column(name = "rp_id")
    private BigInteger rpId;

    @Column(name = "authenticator_credential_id")
    private byte[] authenticatorCredentialId;

    @Column(name = "public_key")
    private byte[] publicKey;

    @Column(name = "sign_count")
    private long sign_count;

    @Column(name = "attestation_format")
    private String attestationFormat;

    @JoinColumn(name = "credential_id")
    @OneToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private List<CredentialConfigEntity> configs;

    @Column(name = "created_at")
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @JoinColumn(name = "authenticator_id", nullable = false)
    @ManyToOne(fetch = FetchType.LAZY)
    private AuthenticatorEntity authenticator;

}
