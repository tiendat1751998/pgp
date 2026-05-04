package com.datdevops.pgp.repository;

import com.datdevops.pgp.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, String> {

    @Query("SELECT a FROM AuditLog a WHERE a.user.id = :userId ORDER BY a.timestamp DESC")
    List<AuditLog> findByUserIdOrderByTimestampDesc(@Param("userId") String userId);

    @Query("SELECT a FROM AuditLog a WHERE a.partner.id = :partnerId ORDER BY a.timestamp DESC")
    List<AuditLog> findByPartnerIdOrderByTimestampDesc(@Param("partnerId") String partnerId);

    @Query("SELECT a FROM AuditLog a WHERE a.timestamp >= :start ORDER BY a.timestamp DESC")
    List<AuditLog> findByTimestampAfter(@Param("start") Instant start);

    @Query("SELECT a FROM AuditLog a WHERE a.action = :action ORDER BY a.timestamp DESC")
    List<AuditLog> findByActionOrderByTimestampDesc(@Param("action") String action);

    @Query("SELECT a FROM AuditLog a WHERE a.correlationId = :correlationId ORDER BY a.timestamp DESC")
    List<AuditLog> findByCorrelationId(@Param("correlationId") String correlationId);
}