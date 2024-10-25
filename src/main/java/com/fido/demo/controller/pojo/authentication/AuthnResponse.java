package com.fido.demo.controller.pojo.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthnResponse {

    @JsonProperty
    private String aaguid;

    @JsonProperty
    private String userId;

    @JsonProperty
    private boolean userVerified;

    @JsonProperty
    private boolean userPresent;
}