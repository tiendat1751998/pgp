package com.datdevops.pgp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app.crypto")
public class CryptoProperties {

    private int corePoolSize = 4;
    private int maxPoolSize = 8;
    private int partnerCacheMaxSize = 10000;
    private int keyCacheMaxSize = 1000;
    private int sessionKeyExpiryMinutes = 30;
    private int replayWindowSeconds = 300;

    public int getCorePoolSize() { return corePoolSize; }
    public void setCorePoolSize(int corePoolSize) { this.corePoolSize = corePoolSize; }
    public int getMaxPoolSize() { return maxPoolSize; }
    public void setMaxPoolSize(int maxPoolSize) { this.maxPoolSize = maxPoolSize; }
    public int getPartnerCacheMaxSize() { return partnerCacheMaxSize; }
    public void setPartnerCacheMaxSize(int partnerCacheMaxSize) { this.partnerCacheMaxSize = partnerCacheMaxSize; }
    public int getKeyCacheMaxSize() { return keyCacheMaxSize; }
    public void setKeyCacheMaxSize(int keyCacheMaxSize) { this.keyCacheMaxSize = keyCacheMaxSize; }
    public int getSessionKeyExpiryMinutes() { return sessionKeyExpiryMinutes; }
    public void setSessionKeyExpiryMinutes(int sessionKeyExpiryMinutes) { this.sessionKeyExpiryMinutes = sessionKeyExpiryMinutes; }
    public int getReplayWindowSeconds() { return replayWindowSeconds; }
    public void setReplayWindowSeconds(int replayWindowSeconds) { this.replayWindowSeconds = replayWindowSeconds; }
}