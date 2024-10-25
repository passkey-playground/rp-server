package com.fido.demo.data.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.util.UUID;
import java.util.List;
import java.math.BigInteger;
import java.time.LocalDateTime;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;


@Entity
@Table(name = "AUTHENTICATORS")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticatorEntity {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "authenticator_sequence_generator")
    @SequenceGenerator(name = "authenticator_sequence_generator", sequenceName = "authenticators_id_seq", allocationSize = 1)
    private BigInteger id;

    @Column(name = "aaguid")
    private UUID aaguid;

    @Column(name = "device_type")
    private String deviceType;

    @Column(name = "transports")
    private List<String> transports;

    @Column(name = "manufacturer")
    private String manufacturer;

    @Column(name = "model")
    private String model;

    @Column(name = "firmware_version")
    private String firmwareVersion;

    @Column(name = "created_at")
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;

//     @JoinColumn(name = "credential_id", nullable = false)
//     @OneToMany(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
//     private List<CredentialEntity> credentials;


}
