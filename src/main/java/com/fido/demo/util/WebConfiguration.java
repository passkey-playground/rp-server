package com.fido.demo.util;


import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfiguration implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                //.allowedOrigins("http://example.com")
                //.allowedOrigins("*")
                .allowedOrigins("https://www.sowmya.com", "http://demo.com", "https://ravikanth-fidotesting.netlify.app", "https://fidotesting-vercel.vercel.app", "https://fidotesting.vercel.app", "https://web2.fidotesting.com")
                .allowCredentials(true)
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowedHeaders("*");
    }
}

