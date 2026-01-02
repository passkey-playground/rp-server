package com.fido.demo.controller.pojo.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fido.demo.controller.pojo.common.ServerPublicKeyCredential;
import lombok.Builder;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;

import java.util.List;

/**
 * NOTE: Same POJO is used as request and response
 */
@Validated
@Data
@Builder
public class RegistrationRequest {

    @NotBlank(message = "id cannot be blank")
    @JsonProperty("id")
    public String id;

    @JsonProperty("rawId")
    public String rawId;

    @JsonProperty("type")
    public String type;

    @JsonProperty("response")
    public ServerPublicKeyCredential.Response response;

}
