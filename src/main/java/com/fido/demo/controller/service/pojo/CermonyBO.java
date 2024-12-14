package com.fido.demo.controller.service.pojo;

import com.fido.demo.controller.pojo.PubKeyCredParam;
import com.fido.demo.controller.pojo.common.RP;
import com.fido.demo.controller.pojo.common.AuthenticatorSelection;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class CermonyBO {

    RP rp;

    AuthenticatorSelection authenticatorSelection;

    String attestation;

    long timeout;

    List<PubKeyCredParam> pubKeyCredPams;

}
