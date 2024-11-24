package com.fido.demo.controller.pojo.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fido.demo.controller.pojo.common.ServerPublicKeyCredential;
import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * NOTE: Same POJO is used as request and response
 */
@Data
@Builder
public class RegRequest {

    /*----------------- Request fields (start) -----------------------------*/
    @JsonProperty("serverPublicKeyCredential")
    private ServerPublicKeyCredential serverPublicKeyCredential;

    @JsonProperty("sessionId")
    private String sessionId;

    @JsonProperty("origin")
    private String origin;

    @JsonProperty("rpId")
    private String rpId;

    @JsonProperty("tokenBinding")
    private String tokenBinding;
    /*----------------- Request fields (end) -----------------------------*/

    /*----------------- Response fields (start) -----------------------------*/
    @JsonProperty("aaguid")
    private String aaguid;

    @JsonProperty("credentialId")
    private String credentialId;

    @JsonProperty("attestationType")
    private String attestationType;

    @JsonProperty("authenticatorTransports")
    private List<String> authenticatorTransports;

    @JsonProperty("userVerified")
    private boolean userVerified;

    @JsonProperty("rk") // resident key or not
    private boolean rk;
    /*----------------- Response fields (end) -----------------------------*/
}
