package com.fido.demo.data.cache;

import com.fido.demo.controller.service.pojo.SessionBO;

/**
 * Cache service interface for storing and retrieving session data.
 * This interface abstracts the underlying caching implementation,
 * allowing for different cache providers (Redis, Memcached, etc.)
 */
public interface CacheService {

    /**
     * Save session data with the specified key
     * @param key the cache key
     * @param data the session data to store
     */
    void save(String key, SessionBO data);

    /**
     * Retrieve session data by key
     * @param key the cache key
     * @return the session data, or null if not found
     */
    SessionBO find(String key);

    /**
     * Delete session data by key
     * @param key the cache key to delete
     */
    void delete(String key);
}
