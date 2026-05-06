package com.datdevops.pgp.service;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Registry for key generator strategies.
 * Implements Strategy Pattern with automatic discovery.
 */
@Component
public class KeyGeneratorRegistry {

    private final Map<String, KeyGeneratorStrategy> strategies;

    public KeyGeneratorRegistry(List<KeyGeneratorStrategy> strategyList) {
        this.strategies = strategyList.stream()
                .collect(Collectors.toMap(
                        KeyGeneratorStrategy::getKeyType,
                        Function.identity()
                ));
    }

    public KeyGeneratorStrategy getStrategy(String keyType) {
        KeyGeneratorStrategy strategy = strategies.get(keyType.toUpperCase());
        if (strategy == null) {
            throw new IllegalArgumentException("Unsupported key type: " + keyType);
        }
        return strategy;
    }

    public boolean supports(String keyType) {
        return strategies.containsKey(keyType.toUpperCase());
    }

    public List<String> getSupportedTypes() {
        return List.copyOf(strategies.keySet());
    }
}