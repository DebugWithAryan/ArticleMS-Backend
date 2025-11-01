package org.aryan.articlemsbackend.service;


import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import lombok.extern.slf4j.Slf4j;
import org.aryan.articlemsbackend.exception.RateLimitExceededException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class RateLimitService {

    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();


    public Bucket resolveBucket(String key) {
        return cache.computeIfAbsent(key, k -> createBucket(100, 1));
    }


    public Bucket resolveAuthBucket(String key) {
        return cache.computeIfAbsent("auth_" + key, k -> createBucket(5, 1));
    }


    private Bucket createBucket(long capacity, int minutes) {
        Bandwidth limit = Bandwidth.classic(
                capacity,
                Refill.intervally(capacity, Duration.ofMinutes(minutes))
        );
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }


    public void checkRateLimit(String key) {
        Bucket bucket = resolveBucket(key);
        if (!bucket.tryConsume(1)) {
            log.warn("Rate limit exceeded for key: {}", key);
            throw new RateLimitExceededException(
                    "Too many requests. Please try again later."
            );
        }
    }


    public void checkAuthRateLimit(String key) {
        Bucket bucket = resolveAuthBucket(key);
        if (!bucket.tryConsume(1)) {
            log.warn("Auth rate limit exceeded for key: {}", key);
            throw new RateLimitExceededException(
                    "Too many login attempts. Please try again after 1 minute."
            );
        }
    }
}

