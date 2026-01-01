package com.fido.demo.controller.pojo.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class PasskeySummary {

    @JsonProperty("username")
    private String username;

    @JsonProperty("credentialId")
    private String credentialId;
}
