package com.fido.demo.controller.pojo.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthnOptionsRequest {

    @JsonProperty("rpId")
    private String rpId;

    @JsonProperty("userId")
    private String userId;

    @JsonProperty("userVerification")
    private String userVerification;

}