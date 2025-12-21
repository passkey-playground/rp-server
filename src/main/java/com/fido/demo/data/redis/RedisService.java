package com.fido.demo.data.redis;

import com.fido.demo.controller.service.pojo.SessionBO;
import com.fido.demo.data.cache.CacheService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RedisService implements CacheService {

    @Autowired
    private RedisTemplate<String, SessionBO> redisTemplate;

    @Override
    public void save(String key, SessionBO data) {
        redisTemplate.opsForValue().set(key, data);
    }

    @Override
    public SessionBO find(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    @Override
    public void delete(String key) {
        redisTemplate.delete(key);
    }
}
