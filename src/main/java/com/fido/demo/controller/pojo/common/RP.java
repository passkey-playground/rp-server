package com.fido.demo.controller.pojo.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RP {
    @JsonProperty("name")
    public String name;

    @JsonProperty("icon")
    public String icon;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("id")
    public String id;

    @JsonProperty("origin")
    public String origin;

}