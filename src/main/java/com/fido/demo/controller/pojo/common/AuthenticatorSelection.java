package com.fido.demo.controller.pojo.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticatorSelection {
    @JsonProperty("authenticatorAttachment")
    public String authenticatorAttachment;

    @JsonProperty("requireResidentKey")
    public boolean requireResidentKey;

    @JsonProperty("userVerification")
    public String userVerification;

    @JsonProperty("residentKey")
    public String residentKey;

    public AuthenticatorSelection() {
    }

}