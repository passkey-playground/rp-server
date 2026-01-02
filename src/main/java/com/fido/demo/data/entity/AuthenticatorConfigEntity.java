package com.fido.demo.data.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigInteger;
import java.sql.Time;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;


@Entity
@Table(name = "AUTHENTICATOR_CONFIGS")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticatorConfigEntity {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "authenticator_sequence_generator")
    @SequenceGenerator(name = "authenticator_sequence_generator", sequenceName = "authenticator_configs_id_seq", allocationSize = 1)
    private BigInteger id;

    @Column(name = "credential_id")
    private int credentialId;

    @Column(name = "setting_key")
    private String settingKey;

    @Column(name = "setting_value")
    private String settingValue;

    @Column(name = "created_at")
    private Time createdAt;

    @Column(name = "updated_at")
    private Time updatedAt;

}


/*
* Sample configs
* coseKey

* */
