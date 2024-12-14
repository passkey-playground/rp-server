package com.fido.demo.controller.service.pojo;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fido.demo.controller.pojo.PubKeyCredParam;
import com.fido.demo.controller.pojo.common.AuthenticatorSelection;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class CermonyConfigs {

    AuthenticatorSelection authenticatorSelection;

    String attestation;

    long timeout;

    List<PubKeyCredParam> pubKeyCredPams;

}
