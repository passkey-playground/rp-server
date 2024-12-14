package com.fido.demo.controller.impl;

import com.fido.demo.controller.api.Authentication;
import com.fido.demo.controller.pojo.authentication.AuthnOptions;
import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import com.fido.demo.controller.pojo.authentication.AuthnResponse;
import com.fido.demo.controller.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component("authenticationController")
public class AuthenticationImpl implements Authentication {

    @Autowired
    AuthenticationService authenticationService;

    @Override
    public ResponseEntity<AuthnOptions> getOptions(AuthnOptions request){
        AuthnOptions response = authenticationService.getAuthNOptions(request);
        return ResponseEntity.ok(response);
    };

    @Override
    public ResponseEntity<AuthnResponse> verifyAssertion(AuthnRequest request){
        AuthnResponse response = authenticationService.authenticate(request);
        return ResponseEntity.ok(response);
    };

}
