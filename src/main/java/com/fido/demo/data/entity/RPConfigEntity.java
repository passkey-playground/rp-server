package com.fido.demo.data.entity;

import java.math.BigInteger;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Entity
@Table(name = "RELYING_PARTY_CONFIGS")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RPConfigEntity {

    @Id
    @Column(name = "id")
    private BigInteger id;

    @Column(name = "rp_id")
    private BigInteger relyingPartyId;

    @Column(name = "setting_key")
    private String settingKey;

    @Column(name = "setting_value")
    private String settingValue;

}
