package com.datdevops.pgp.repository;

import com.datdevops.pgp.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Repository
public interface AuditRepository extends JpaRepository<AuditLog, String> {
    List<AuditLog> findByCorrelationId(String correlationId);

    @Modifying
    @Transactional
    @Query("DELETE FROM AuditLog a WHERE a.timestamp < :cutoff")
    void deleteOlderThan(Instant cutoff);
}
