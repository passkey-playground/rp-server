package com.fido.demo.controller.api.impl;

import com.fido.demo.controller.api.RegistrationController;
import com.fido.demo.controller.pojo.registration.RegOptions;
import com.fido.demo.controller.pojo.registration.RegOptionsRequest;
import com.fido.demo.controller.pojo.registration.RegRequest;
import com.fido.demo.controller.pojo.registration.RegistrationRequest;
import com.fido.demo.controller.service.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component("registartionController")
public class RegistartionControllerImpl implements RegistrationController {

    @Autowired
    RegistrationService registrationService;

    @Override
    public ResponseEntity<RegOptions> registrationOptions(RegOptionsRequest request) {
        RegOptions regOptionsResponse = registrationService.getRegOptions(request);
        return ResponseEntity.ok(regOptionsResponse);
    }

    //@Override
    public ResponseEntity<RegOptions> getRegOptions(RegOptions request) {
        RegOptions regOptionsResponse = registrationService.getRegOptions(request);
        return ResponseEntity.ok(regOptionsResponse);
    }

    @Override
    public ResponseEntity<RegRequest> registration(RegistrationRequest request) {
        RegRequest regResponse = registrationService.createRegistration(request);
        return ResponseEntity.ok(regResponse);
    }

    //@Override
    public ResponseEntity<RegOptions> attestationOptions(RegOptionsRequest request) {
        return registrationOptions(request);
    }

    //@Override
    public ResponseEntity<RegRequest> attestation(RegistrationRequest request) {
        return registration(request);
    }

}