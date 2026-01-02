package com.fido.demo.controller.ui;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/fido2")
public class PasskeyController {

    @GetMapping("/ui")
    public String passkeyUi() {
        return "forward:/passkey/index.html";
    }
}
