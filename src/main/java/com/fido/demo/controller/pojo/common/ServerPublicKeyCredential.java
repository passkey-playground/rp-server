package com.fido.demo.controller.pojo.common;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class ServerPublicKeyCredential {
    @JsonProperty("id")
    public String id;
    @JsonProperty("type")
    public String type;
    @JsonProperty("response")
    public Response response;
    @JsonProperty("extensions")
    public Extensions extensions;

    @Data
    public static class Response {

        @JsonProperty("clientDataJSON")
        private String clientDataJSON;

        @JsonProperty("attestationObject")
        private String attestationObject;

        @JsonProperty("authenticatorData")
        private String authenticatorData;

        @JsonProperty("publicKey")
        private String publicKey;

        @JsonProperty("transports")
        private List<String> transports;

        @JsonProperty
        private String userHandle;

        @JsonProperty("signature")
        private String signature;
    }
    @Data
    public static class Extensions {

        @JsonProperty("appid")
        private String appid;

        @JsonProperty("txAuthSimple")
        private String txAuthSimple;

        @JsonProperty("txAuthGeneric")
        private String txAuthGeneric;

        @JsonProperty("authnSel")
        private String authnSel;

        @JsonProperty("exts")
        private String exts;

        @JsonProperty("uvi")
        private String uvi;

        @JsonProperty("loc")
        private String loc;

        @JsonProperty("biometricPerfBounds")
        private String biometricPerfBounds;

        @JsonProperty("credProps")
        private CredProps credProps;

    }

    @Data
    public static class CredProps {

        @JsonProperty("rk")
        private boolean rk;

        // Getters and Setters
        public boolean isRk() {
            return rk;
        }

        public void setRk(boolean rk) {
            this.rk = rk;
        }
    }
}

