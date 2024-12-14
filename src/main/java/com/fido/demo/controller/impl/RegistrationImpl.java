package com.fido.demo.controller.impl;

import com.fido.demo.controller.api.Registration;
import com.fido.demo.controller.pojo.registration.RegOptionsResponse;
import com.fido.demo.controller.pojo.registration.RegOptionsRequest;
import com.fido.demo.controller.pojo.registration.RegistrationResponse;
import com.fido.demo.controller.pojo.registration.RegistrationRequest;
import com.fido.demo.controller.service.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component("registartionController")
public class RegistrationImpl implements Registration {

    @Autowired
    RegistrationService registrationService;

    @Override
    public ResponseEntity<RegOptionsResponse> getOptions(RegOptionsRequest request) {
        RegOptionsResponse regOptionsResponse = registrationService.getRegOptions(request);
        return ResponseEntity.ok(regOptionsResponse);
    }

    @Override
    public ResponseEntity<RegistrationResponse> verifyAttestation(RegistrationRequest request) {
        RegistrationResponse regResponse = registrationService.createRegistration(request);
        return ResponseEntity.ok(regResponse);
    }

}