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

@Entity
@Table(name = "CREDENTIAL_CONFIGS")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CredentialConfigEntity {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "cred_sequence_generator")
    @SequenceGenerator(name = "cred_sequence_generator", sequenceName = "credential_configs_id_seq", allocationSize = 1)
    private BigInteger id;

    @JoinColumn(name = "credential_id")
    @ManyToOne(fetch = FetchType.LAZY)
    private CredentialEntityOld credentialEntity;

    @Column(name = "setting_key")
    private String settingKey;

    @Column(name = "setting_value")
    private String settingValue;

    @Column(name = "created_at")
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;

}
