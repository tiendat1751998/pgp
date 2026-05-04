package com.datdevops.pgp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app.feature")
public class FeatureFlags {

    private boolean mtlsEnabled = true;
    private boolean legacyAuthEnabled = false;
    private boolean allowBodySenderId = false;

    public boolean isMtlsEnabled() {
        return mtlsEnabled;
    }

    public void setMtlsEnabled(boolean mtlsEnabled) {
        this.mtlsEnabled = mtlsEnabled;
    }

    public boolean isLegacyAuthEnabled() {
        return legacyAuthEnabled;
    }

    public void setLegacyAuthEnabled(boolean legacyAuthEnabled) {
        this.legacyAuthEnabled = legacyAuthEnabled;
    }

    public boolean isAllowBodySenderId() {
        return allowBodySenderId;
    }

    public void setAllowBodySenderId(boolean allowBodySenderId) {
        this.allowBodySenderId = allowBodySenderId;
    }
}