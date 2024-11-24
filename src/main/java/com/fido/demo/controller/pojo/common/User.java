package com.fido.demo.controller.pojo.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @JsonProperty("name")
    public String name;

    @JsonProperty("icon")
    public String icon;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("id")
    public String id;

    @JsonProperty("displayName")
    public String displayName;

}