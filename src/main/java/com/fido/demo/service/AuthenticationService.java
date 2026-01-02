package com.fido.demo.service;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.fido.demo.service.pojo.*;

@RestController
@RequestMapping("/fido2")
class AuthenticationService {
    
    // Get challenge options for registration
    @PostMapping("/authentication/options")
    public AuthenticationOptionsResponse getRegOptions(AuthenticationOptionsRequest request) {
        return null;
    }

    @PostMapping("/authentication")
    public AuthenticationResponse createRegistration(AuthenticationRequest request){
        return null;
    }
}