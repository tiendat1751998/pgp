package com.datdevops.pgp.config;

import com.datdevops.pgp.security.MTLSAuthenticationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfiguration {

    @Bean
    public FilterRegistrationBean<MTLSAuthenticationFilter> mtlsFilterRegistration(MTLSAuthenticationFilter filter) {
        FilterRegistrationBean<MTLSAuthenticationFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/api/*");
        registration.setOrder(1);
        registration.setName("mtlsAuthFilter");
        return registration;
    }
}