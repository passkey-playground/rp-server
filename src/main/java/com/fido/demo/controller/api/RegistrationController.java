package com.fido.demo.controller.api;

import com.fido.demo.controller.pojo.registration.RegOptions;
import com.fido.demo.controller.pojo.registration.RegOptionsRequest;
import com.fido.demo.controller.pojo.registration.RegRequest;
import com.fido.demo.controller.pojo.registration.RegistrationRequest;
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
    @PostMapping(value = {"/registration/options", "/attestation/options"}, consumes = "application/json")
    ResponseEntity<RegOptions> registrationOptions(@RequestBody RegOptionsRequest request) ;

    @PostMapping(value = {"/registration", "/attestation/result"})
    ResponseEntity<RegRequest> registration(@RequestBody RegistrationRequest request);

    /* old interfaces

    //@PostMapping(value = "/attestation/options", consumes = "application/json")
    ResponseEntity<RegOptions> attestationOptions(@RequestBody RegOptionsRequest request) ;

    //@PostMapping("/attestation/result")
    ResponseEntity<RegRequest> attestation(@RequestBody RegistrationRequest request);

    @PostMapping(value = "/registration/options", consumes = "application/json")
    ResponseEntity<RegOptions> getRegOptions(@RequestBody RegOptions request) ;

    @PostMapping(value = "/attestation/options", consumes = "application/json")
    ResponseEntity<RegOptions> getAttestationOptions(@RequestBody RegOptions request) ;

    @PostMapping("/attestation/result")
    ResponseEntity<RegRequest> createAttestation(@RequestBody RegRequest request);

    */


}