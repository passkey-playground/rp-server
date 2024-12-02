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
public class RegistrationRequest {

    /*----------------- Request fields (start) -----------------------------*/
    @JsonProperty("id")
    public String id;

    @JsonProperty("rawId")
    public String rawId;

    @JsonProperty("type")
    public String type;

    @JsonProperty("response")
    public ServerPublicKeyCredential.Response response;

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
