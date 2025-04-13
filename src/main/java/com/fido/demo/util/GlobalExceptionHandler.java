package com.fido.demo.util;

import com.fido.demo.controller.pojo.ApiError;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.data.rest.webmvc.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @Autowired
    private Environment environment;

    // Handle specific exceptions
    @ExceptionHandler(ResourceNotFoundException.class)
    public final ResponseEntity<ApiError> handleResourceNotFoundException(ResourceNotFoundException ex, WebRequest request) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());
        ApiError error = new ApiError(HttpStatus.NOT_FOUND, "Resource Not Found", details);
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }


    // Handle generic exceptions
    @ExceptionHandler(Exception.class)
    public final ResponseEntity<ApiError> handleAllExceptions(Exception ex, WebRequest request) {

        List<String> details = new ArrayList<>();
        details.add(ex.getMessage());


        ApiError error = new ApiError(HttpStatus.INTERNAL_SERVER_ERROR, "Server Error", details);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    // Handle validation errors
    //@Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatus status,
            WebRequest request) {

        List<String> errors = new ArrayList<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.add(error.getField() + ": " + error.getDefaultMessage());
        }

        System.err.println("-----------------------");
        System.err.println("it is also coming here....");
        System.err.println("-----------------------");
        ApiError apiError = new ApiError(HttpStatus.BAD_REQUEST, "Validation Failed", errors);
        return new ResponseEntity<>(apiError, HttpStatus.BAD_REQUEST);
    }

}
