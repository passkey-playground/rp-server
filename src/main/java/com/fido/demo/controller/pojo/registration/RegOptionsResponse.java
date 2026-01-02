package com.fido.demo.controller.pojo.registration;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fido.demo.controller.pojo.PubKeyCredParam;
import com.fido.demo.controller.pojo.common.AuthenticatorSelection;
import com.fido.demo.controller.pojo.common.RP;
import com.fido.demo.controller.pojo.common.User;
import com.fido.demo.data.entity.CredentialEntity;
import lombok.*;

import java.util.List;
import java.util.Map;

@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RegOptionsResponse {

    @JsonProperty(value = "status")
    @Builder.Default
    private String status = "ok";

    @JsonProperty(value = "errorMessage")
    @Builder.Default
    private String errorMessage = "";

    @JsonProperty("rp")
    private RP rp;

    @JsonProperty("user")
    private User user;

    @JsonProperty("challenge")
    private String challenge;

    @JsonProperty("pubKeyCredParams")
    private List<PubKeyCredParam> pubKeyCredParams;

    @JsonProperty("authenticatorSelection")
    private AuthenticatorSelection authenticatorSelection;

    @JsonProperty("attestation")
    private String attestation;

    @JsonProperty("excludeCredentials") //ToDo : define a type here
    private List<Map<String,String>> excludeCredentials;

    /*------------ below fields are not needed ---------------------------*/

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("credProtect")
    private String credProtect;

    @JsonProperty("timeout")
    private long timeout;


    @JsonProperty("sessionId")
    private String sessionId;

    @JsonProperty("extensions")
    private Map<String, Object> extensions;

    @JsonProperty("serverResponse")
    private ServerResponse serverResponse;

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

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getInternalError() {
            return internalError;
        }

        public void setInternalError(String internalError) {
            this.internalError = internalError;
        }

        public int getInternalErrorCode() {
            return internalErrorCode;
        }

        public void setInternalErrorCode(int internalErrorCode) {
            this.internalErrorCode = internalErrorCode;
        }

        public String getInternalErrorCodeDescription() {
            return internalErrorCodeDescription;
        }

        public void setInternalErrorCodeDescription(String internalErrorCodeDescription) {
            this.internalErrorCodeDescription = internalErrorCodeDescription;
        }
    }


    /*
    public static class Extensions {

        @JsonProperty("credProps")
        private boolean credProps;

        public boolean isCredProps() {
            return credProps;
        }

        public void setCredProps(boolean credProps) {
            this.credProps = credProps;
        }
    }*/

}
