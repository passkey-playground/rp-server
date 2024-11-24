package com.fido.demo.controller.api;

import com.fido.demo.controller.pojo.registration.RegOptions;
import com.fido.demo.controller.pojo.registration.RegRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * Controller for "registration"
 * NOTE: though there are two flavors "/registration" and "/attestation",
 * both serve same purpose and share implementation
 */
@RestController
@RequestMapping("/fido2")
public interface RegistrationController {

    // Get challenge options for registration
    @PostMapping(value = "/registration/options", consumes = "application/json")
    public ResponseEntity<RegOptions> getRegOptions(@RequestBody RegOptions request) ;

    @PostMapping("/registration")
    public ResponseEntity<RegRequest> createRegistration(@RequestBody RegRequest request);

    @PostMapping(value = "/attestation/options", consumes = "application/json")
    public ResponseEntity<RegOptions> getAttestationOptions(@RequestBody RegOptions request) ;

    @PostMapping("/attestation")
    public ResponseEntity<RegRequest> createAttestation(@RequestBody RegRequest request);
}