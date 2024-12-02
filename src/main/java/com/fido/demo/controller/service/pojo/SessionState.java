package com.fido.demo.controller.service.pojo;

import java.math.BigInteger;

import com.fido.demo.controller.pojo.common.RP;
import com.fido.demo.controller.pojo.common.AuthenticatorSelection;
import com.fido.demo.controller.pojo.common.User;
import lombok.Builder;
import lombok.Data;
import lombok.extern.jackson.Jacksonized;

@Data
@Builder
@Jacksonized
public class SessionState {
    private String sessionId;

    private RP rp;

    private String rpId;

    private User user;

    private String challenge;

    private BigInteger rpDbId;

    private BigInteger userDbId;

    private AuthenticatorSelection authenticatorSelection;

    private long timeout;

}
