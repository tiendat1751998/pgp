package com.datdevops.pgp.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableJpaRepositories(basePackages = "com.datdevops.pgp.repository")
@EnableJpaAuditing
@EnableTransactionManagement
@EntityScan(basePackages = "com.datdevops.pgp.entity")
@Profile("production")
public class DatabaseConfig {

    @Autowired
    private DataSource dataSource;

    @Bean
    @Primary
    public LocalContainerEntityManagerFactoryBean entityManagerFactory(EntityManagerFactoryBuilder builder) {
        Map<String, Object> props = new HashMap<>();
        props.put("hibernate.hbm2ddl.auto", "validate");
        props.put("hibernate.jdbc.time_zone", "UTC");
        props.put("hibernate.order_updates", true);
        props.put("hibernate.order_inserts", true);
        return builder
            .dataSource(dataSource)
            .packages("com.datdevops.pgp.entity")
            .properties(props)
            .build();
    }
}