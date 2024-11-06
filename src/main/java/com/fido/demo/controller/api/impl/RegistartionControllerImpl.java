package com.fido.demo.controller.api.impl;

import com.fido.demo.controller.api.RegistrationController;
import com.fido.demo.controller.pojo.registration.options.RegOptions;
import com.fido.demo.controller.pojo.registration.RegRequest;
import com.fido.demo.controller.pojo.registration.RegResponse;
import com.fido.demo.controller.service.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;



@Component("registartionController")
public class RegistartionControllerImpl implements RegistrationController {

    @Autowired
    RegistrationService registrationService;

    @Override
    public ResponseEntity<RegOptions> getRegOptions(RegOptions request) {
        RegOptions regOptionsResponse = registrationService.getRegOptions(request);
        return ResponseEntity.ok(regOptionsResponse);
    }

    @Override
    public ResponseEntity<RegRequest> createRegistration(RegRequest request) {
        RegRequest regResponse = registrationService.getReg(request);
        return ResponseEntity.ok(regResponse);
    }

    @Override
    public ResponseEntity<RegOptions> getAttestationOptions(RegOptions request) {
        return getRegOptions(request);
    }

    @Override
    public ResponseEntity<RegRequest> createAttestation(RegRequest request) {
        return createRegistration(request);
    }

}