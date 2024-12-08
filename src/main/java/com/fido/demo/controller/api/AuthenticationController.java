package com.fido.demo.controller.api;

import com.fido.demo.controller.pojo.authentication.AuthnOptions;
import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import com.fido.demo.controller.pojo.authentication.AuthnResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/fido2")
public interface AuthenticationController {

    // Get challenge options for registration
    @PostMapping("/authentication/options")
    public ResponseEntity<AuthnOptions> getAuthnOptions(@RequestBody AuthnOptions request);

    @PostMapping("/authentication")
    public ResponseEntity<AuthnResponse> verifyAuthentication(@RequestBody AuthnRequest request);

    @PostMapping("/assertion/options")
    public ResponseEntity<AuthnOptions> getAssertionOptions(@RequestBody AuthnOptions request);

    @PostMapping("/assertion/result")
    public ResponseEntity<AuthnResponse> verifyAssertion(@RequestBody AuthnRequest request);
}