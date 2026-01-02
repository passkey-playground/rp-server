package com.fido.demo.service.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data // for getters and setters
@NoArgsConstructor
public class RegOptionsRequest {

    @JsonProperty("rp")
    private RP rp;

    @JsonProperty("user")
    private User user;

    @JsonProperty("authenticatorSelection")
    private AuthenticatorSelection authenticatorSelection;

    @JsonProperty("attestation")
    private String attestation;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("credProtect")
    private String credProtect;

    // Getters and Setters

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

    public static class AuthenticatorSelection {

        @JsonProperty("authenticatorAttachment")
        private String authenticatorAttachment;

        @JsonProperty("requireResidentKey")
        private boolean requireResidentKey;

        @JsonProperty("userVerification")
        private String userVerification;

        // Getters and Setters
    }
}
