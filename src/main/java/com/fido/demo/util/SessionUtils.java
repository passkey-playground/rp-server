package com.fido.demo.util;



import com.fido.demo.controller.pojo.authentication.AuthnOptions;
import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import com.fido.demo.controller.service.pojo.CermonyBO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fido.demo.controller.service.pojo.SessionBO;
import com.fido.demo.data.cache.CacheService;
import com.fido.demo.data.entity.RelyingPartyEntity;
import com.fido.demo.data.entity.UserEntity;

import java.util.Base64;
import com.fido.demo.controller.pojo.common.RP;
import com.fido.demo.controller.pojo.common.User;


@Component
public class SessionUtils {

    @Autowired
    CacheService cacheService;

    @Autowired
    CryptoUtil cryptoUtil;

    @Autowired
    RpUtils rpUtils;

    public SessionBO persistAttestationState(User user,
                                             String challenge,
                                             CermonyBO cermonyBO){
        SessionBO state = SessionBO.builder()
                .sessionId(challenge) // use challenge as session key
                .challenge(challenge)
                .rpId(cermonyBO.getRp().getId())
                .rp(cermonyBO.getRp())
                .user(user)
                .authenticatorSelection(cermonyBO.getAuthenticatorSelection())
                .timeout(cermonyBO.getTimeout())
                .build();
        cacheService.save(challenge, state);
        return state;
    }

    public SessionBO retrieveSession(AuthnRequest request){
        SessionBO session = (SessionBO) cacheService.find(request.getSessionId());
        return session;
    }

}
