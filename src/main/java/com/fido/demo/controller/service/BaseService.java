package com.fido.demo.controller.service;

import com.fido.demo.data.redis.RedisService;
import com.fido.demo.data.repository.CredentialRepository;
import com.fido.demo.data.repository.RPRepository;
import com.fido.demo.data.repository.UserRepository;
import com.fido.demo.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

//ToDo: Move all the validations to validators
@Component
class BaseService {
    // grouping all autowired dependencies here
    @Autowired
    RPRepository rpRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    SessionUtils sessionUtils;

    @Autowired
    CredentialRepository credentialRepository;

    @Autowired
    CredUtils credUtils;

    @Autowired
    CryptoUtil cryptoUtil;

    @Autowired
    RedisService redisService;

    @Autowired
    Base64Utils base64Utils;

    @Autowired
    UserUtils userUtils;

    @Autowired
    RpUtils rpUtils;


}
