package com.fido.demo.controller.api;

import com.fido.demo.controller.pojo.authentication.AuthnOptions;
import com.fido.demo.controller.pojo.authentication.AuthnRequest;
import com.fido.demo.controller.pojo.authentication.AuthnResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/fido2")
public interface Authentication {

    @PostMapping(value = {"/assertion/options", "/authentication/options"})
    ResponseEntity<AuthnOptions> getOptions(@RequestBody AuthnOptions request,
                                            @RequestHeader("rp_id") String rpId);

    @PostMapping(value = {"/assertion/result", "/authentication"})
    ResponseEntity<AuthnResponse> verifyAssertion(@RequestBody AuthnRequest request,
                                                  @RequestHeader("rp_id") String rpId);
}