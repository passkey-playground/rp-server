package com.fido.demo.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "RP Server API",
                version = "1.0.0",
                description = "FIDO2/WebAuthn relying party endpoints for registration and authentication."
        ),
        servers = {
                @Server(url = "http://localhost:8090", description = "Local")
        }
)
public class OpenApiConfig {
}
