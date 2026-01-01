package com.fido.demo.controller.pojo.authentication;

import lombok.Builder;
import lombok.Data;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class AuthnOptions {

    @JsonProperty(value = "status")
    @Builder.Default
    private String status = "ok";

    @JsonProperty(value = "errorMessage")
    @Builder.Default
    private String errorMessage = "";


    @JsonProperty("username")
    private String username;

    // <----------------------- Request field(start) ------------------->
    @JsonProperty("rpId")
    private String rpId;

    @JsonProperty("userVerification")
    String userVerification;

    @JsonProperty("userId")
    private String userId;
    // <-----------------------Request fields(end)----------------------->

    @JsonProperty("challenge")
    private String challenge;

    @JsonProperty("timeout")
    private long timeout;


    @JsonProperty("sessionId")
    private String sessionId;

    @JsonProperty("allowCredentials")
    private List<Map<String,String>> allowedCreds;

    @JsonProperty("registeredPasskeys")
    private List<PasskeySummary> registeredPasskeys;

}

