package com.fido.demo.util.webauthn4j;

import com.webauthn4j.WebAuthnRegistrationManager;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class WebAuthnUtils {

    private WebAuthnRegistrationManager registrationManager;

    @PostConstruct
    void postConstruct(){
        registrationManager = WebAuthnRegistrationManager.createNonStrictWebAuthnRegistrationManager();
    }

    public RegistrationData parse(RegistrationRequest request){
        return registrationManager.parse(request);
    }

    public RegistrationData verify(RegistrationData data, RegistrationParameters parameters){
        return registrationManager.verify(data, parameters);
    }
}
