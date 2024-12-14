package com.fido.demo.controller.api;

import com.fido.demo.controller.pojo.registration.RegOptionsResponse;
import com.fido.demo.controller.pojo.registration.RegOptionsRequest;
import com.fido.demo.controller.pojo.registration.RegistrationResponse;
import com.fido.demo.controller.pojo.registration.RegistrationRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * Controller for "registration"
 * NOTE: though there are two flavors "/registration*" and "/attestation*",
 * both serve same purpose and share same implementation
 */
@RestController
@RequestMapping("/fido2")
public interface Registration {

    @PostMapping(value = {"/registration/options", "/attestation/options"}, consumes = "application/json")
    ResponseEntity<RegOptionsResponse> getOptions(@RequestBody RegOptionsRequest request) ;

    @PostMapping(value = {"/registration/result", "/attestation/result"})
    ResponseEntity<RegistrationResponse> verifyAttestation(@RequestBody RegistrationRequest request);
}