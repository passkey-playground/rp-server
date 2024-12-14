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
public class RegistrationResponse {


    /*----------------- Response fields (start) -----------------------------*/

    @JsonProperty(value = "status")
    @Builder.Default
    private String status = "ok";

    @JsonProperty(value = "errorMessage")
    @Builder.Default
    private String errorMessage = "";

}
