
package com.fido.demo.service.pojo;


import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data // for getters and setters
@NoArgsConstructor
public class RegOptionsResponse {

    @JsonProperty("serverResponse")
    private ServerResponse serverResponse;

    @JsonProperty("rp")
    private RP rp;

    @JsonProperty("user")
    private User user;

    @JsonProperty("challenge")
    private String challenge;

    @JsonProperty("pubKeyCredParams")
    private List<PubKeyCredParam> pubKeyCredParams;

    @JsonProperty("timeout")
    private long timeout;

    @JsonProperty("excludeCredentials")
    private List<Object> excludeCredentials;

    @JsonProperty("authenticatorSelection")
    private AuthenticatorSelection authenticatorSelection;

    @JsonProperty("attestation")
    private String attestation;

    @JsonProperty("sessionId")
    private String sessionId;

    @JsonProperty("extensions")
    private Extensions extensions;

    // Getters and Setters

    public static class ServerResponse {

        @JsonInclude(JsonInclude.Include.NON_NULL)
        @JsonProperty("description")
        private String description;

        @JsonProperty("internalError")
        private String internalError;

        @JsonProperty("internalErrorCode")
        private int internalErrorCode;

        @JsonInclude(JsonInclude.Include.NON_NULL)
        @JsonProperty("internalErrorCodeDescription")
        private String internalErrorCodeDescription;

        // Getters and Setters
    }

    public static class RP {

        @JsonProperty("name")
        private String name;

        @JsonInclude(JsonInclude.Include.NON_NULL)
        @JsonProperty("icon")
        private String icon;

        @JsonProperty("id")
        private String id;

        // Getters and Setters
    }

    public static class User {

        @JsonProperty("name")
        private String name;

        @JsonInclude(JsonInclude.Include.NON_NULL)
        @JsonProperty("icon")
        private String icon;

        @JsonProperty("id")
        private String id;

        @JsonProperty("displayName")
        private String displayName;

        // Getters and Setters
    }

    public static class PubKeyCredParam {

        @JsonProperty("type")
        private String type;

        @JsonProperty("alg")
        private int alg;

        // Getters and Setters
    }

    public static class AuthenticatorSelection {

        @JsonProperty("authenticatorAttachment")
        private String authenticatorAttachment;

        @JsonProperty("requireResidentKey")
        private boolean requireResidentKey;

        @JsonProperty("userVerification")
        private String userVerification;

        // Getters and Setters
    }

    public static class Extensions {

        @JsonProperty("credProps")
        private boolean credProps;

        // Getters and Setters
    }
}
