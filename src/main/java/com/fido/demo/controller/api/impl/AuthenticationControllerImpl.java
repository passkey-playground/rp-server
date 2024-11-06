package com.fido.demo.controller.api.impl;

import com.fido.demo.controller.api.AuthenticationController;
import com.fido.demo.controller.pojo.authentication.AuthenticationOptionsRequest;
import com.fido.demo.controller.pojo.authentication.AuthenticationOptionsResponse;
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

    @Override
    public ResponseEntity<AuthenticationOptionsResponse> getRegOptions(AuthenticationOptionsRequest request) {
        AuthenticationOptionsResponse response = authenticationService.getAuthNOptions(request);
        return ResponseEntity.ok(response);
    }

    @Override
    public ResponseEntity<AuthnResponse> createRegistration(AuthnRequest request) {
        AuthnResponse response = authenticationService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    @Override
    public ResponseEntity<AuthenticationOptionsResponse> getAssertionOptions(AuthenticationOptionsRequest request){
        return getRegOptions(request);
    };

    @Override
    public ResponseEntity<AuthnResponse> verifyAssertion(AuthnRequest request){
        return createRegistration(request);
    };

}
