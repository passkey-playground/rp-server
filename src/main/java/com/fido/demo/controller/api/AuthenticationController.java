package com.fido.demo.controller.api;

import com.fido.demo.controller.pojo.authentication.AuthenticationOptionsRequest;
import com.fido.demo.controller.pojo.authentication.AuthenticationOptionsResponse;
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
    public ResponseEntity<AuthenticationOptionsResponse> getRegOptions(@RequestBody AuthenticationOptionsRequest request);

    @PostMapping("/authentication")
    public ResponseEntity<AuthnResponse> createRegistration(@RequestBody AuthnRequest request);

    @PostMapping("/assertion/options")
    public ResponseEntity<AuthenticationOptionsResponse> getAssertionOptions(@RequestBody AuthenticationOptionsRequest request);

    @PostMapping("/assertion")
    public ResponseEntity<AuthnResponse> verifyAssertion(@RequestBody AuthnRequest request);
}