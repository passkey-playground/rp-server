package com.fido.demo.controller.api.impl;

import com.fido.demo.controller.api.AuthenticationController;
import com.fido.demo.controller.pojo.authentication.AuthnOptions;
import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import com.fido.demo.controller.pojo.authentication.AuthnResponse;
import com.fido.demo.controller.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component("authenticationController")
public class AuthenticationControllerImpl implements AuthenticationController {

    @Autowired
    AuthenticationService authenticationService;

    public ResponseEntity<AuthnOptions> getAuthnOptions(AuthnOptions request) {
        AuthnOptions response = authenticationService.getAuthNOptions(request);
        return ResponseEntity.ok(response);
    }

    public ResponseEntity<AuthnResponse> verifyAuthentication(AuthnRequest request) {
        AuthnResponse response = authenticationService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    @Override
    public ResponseEntity<AuthnOptions> getAssertionOptions(AuthnOptions request){
        return getAuthnOptions(request);
    };

    @Override
    public ResponseEntity<AuthnResponse> verifyAssertion(AuthnRequest request){
        return verifyAuthentication(request);
    };

}
