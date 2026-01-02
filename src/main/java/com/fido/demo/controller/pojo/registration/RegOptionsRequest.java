package com.fido.demo.controller.pojo.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fido.demo.controller.pojo.common.AuthenticatorSelection;
import lombok.Builder;
import lombok.Data;

import java.util.Map;

// Conformant API Spec
@Data
@Builder
public class RegOptionsRequest {

    @JsonProperty("username")
    private String userName;

    @JsonProperty("displayName")
    private String displayName;

    @JsonProperty("authenticatorSelection")
    private AuthenticatorSelection authenticatorSelection;

    @JsonProperty("attestation")
    private String attestation;

    @JsonProperty("extensions")
    private Map<String, Object> extensions;

}
