package com.fido.demo.util;



import com.fido.demo.controller.pojo.authentication.AuthnOptions;
import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fido.demo.controller.service.pojo.SessionState;
import com.fido.demo.data.entity.RelyingPartyEntity;
import com.fido.demo.data.entity.UserEntity;
import com.fido.demo.data.redis.RedisService;

import java.util.Base64;
import com.fido.demo.controller.pojo.common.RP;
import com.fido.demo.controller.pojo.common.User;


@Component
public class SessionUtils {

    @Autowired
    RedisService redisService;

    @Autowired
    CryptoUtil cryptoUtil;

    @Autowired
    RpUtils rpUtils;

    public SessionState retrieveSession(AuthnRequest request){
        SessionState session = (SessionState) redisService.find(request.getSessionId());
        return session;
    }

    public SessionState getAuthnSession(AuthnOptions request, RelyingPartyEntity rpEntity, UserEntity userEntity){
        String sessionId = cryptoUtil.generateSecureRandomString(32);

        String challenge = cryptoUtil.generateSecureRandomString(32);
        String challengeBase64 = Base64.getEncoder().encodeToString(challenge.getBytes());

        // ToDO: build RP from rpEntity not from incoming request
        RP rp = RP.builder()
                .id(request.getRpId())
                .origin(rpEntity.getOrigin())
                .build();

        User user = User.builder()
        .displayName(userEntity.getDisplayName())
        .id(userEntity.getUserId())
        .build();

        long timeout = rpUtils.getTimeout(rpEntity.getConfigs());

        SessionState state = SessionState.builder() // ToDo : instead of saving the incoming data without validation, validate and persist
                .sessionId(sessionId)
                .rp(rp)
                .user(user)
                .challenge(challengeBase64)
                .timeout(timeout)
                .rpDbId(rpEntity.getId())
                .userDbId(userEntity.getId())
                .build();

        redisService.save(sessionId, state); // save the state for subsequent calls

        return state;
    }

}
