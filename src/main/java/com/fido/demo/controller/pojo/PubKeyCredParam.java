package com.fido.demo.controller.pojo;

import lombok.Builder;
import lombok.Data;

import com.fasterxml.jackson.annotation.JsonProperty;

@Data
@Builder
public class PubKeyCredParam {

    @JsonProperty("type")
    private String type;

    @JsonProperty("alg")
    private int alg;

}

