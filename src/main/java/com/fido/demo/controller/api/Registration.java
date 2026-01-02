package com.fido.demo.controller.api;

import com.fido.demo.controller.pojo.registration.RegOptionsResponse;
import com.fido.demo.controller.pojo.registration.RegOptionsRequest;
import com.fido.demo.controller.pojo.registration.RegistrationResponse;
import com.fido.demo.controller.pojo.registration.RegistrationRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.validation.Valid;


/**
 * Controller for "registration"
 * NOTE: though there are two flavors "/registration*" and "/attestation*",
 * both serve same purpose and share same implementation
 */
@RestController
@RequestMapping("/fido2")
public interface Registration {

    @PostMapping(value = {"/registration/options", "/attestation/options"}, consumes = "application/json")
    ResponseEntity<RegOptionsResponse> getOptions(@RequestBody RegOptionsRequest request,
    @RequestHeader(name = "rp_id", required = false) String rpId) ;

    @PostMapping(value = {"/registration/result", "/attestation/result"})
    ResponseEntity<RegistrationResponse> verifyAttestation(@Valid @RequestBody RegistrationRequest request,
    @RequestHeader(value = "rp_id", required = false) String rpId);
}