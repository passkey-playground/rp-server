package com.fido.demo.service;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.fido.demo.service.pojo.*;

@RestController
@RequestMapping("/fido2")
class RegistrationService {
    
    // Get challenge options for registration
    @GetMapping("/registration/options")
    public RegOptionsResponse getRegOptions(RegOptionsRequest request) {
        return null;
    }

    @PostMapping("/registration")
    public RegistrationResponse createRegistration(RegistrationRequest request){
        return null;
    }
}