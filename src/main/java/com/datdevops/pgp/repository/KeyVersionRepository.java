package com.datdevops.pgp.repository;

import com.datdevops.pgp.entity.KeyVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface KeyVersionRepository extends JpaRepository<KeyVersion, Long> {

    @Query("SELECT k FROM KeyVersion k WHERE k.ownerId = :ownerId AND k.keyType = :keyType AND k.active = true ORDER BY k.version DESC LIMIT 1")
    Optional<KeyVersion> findActiveKey(@Param("ownerId") String ownerId, @Param("keyType") String keyType);

    @Query("SELECT k FROM KeyVersion k WHERE k.ownerId = :ownerId AND k.keyType = :keyType AND k.version = :version")
    Optional<KeyVersion> findByOwnerAndTypeAndVersion(@Param("ownerId") String ownerId, @Param("keyType") String keyType, @Param("version") Integer version);

    @Query("SELECT k FROM KeyVersion k WHERE k.ownerId = :ownerId AND k.keyType = :keyType ORDER BY k.version DESC")
    List<KeyVersion> findByOwnerAndType(@Param("ownerId") String ownerId, @Param("keyType") String keyType);

    @Query("SELECT k FROM KeyVersion k WHERE k.ownerId = :ownerId AND k.keyType = :keyType ORDER BY k.version DESC")
    List<KeyVersion> findByOwnerAndTypeOrderByVersionDesc(@Param("ownerId") String ownerId, @Param("keyType") String keyType);

    @Query("SELECT k FROM KeyVersion k WHERE k.validTo IS NOT NULL AND k.validTo < :now")
    List<KeyVersion> findExpiredKeys(@Param("now") Instant now);

    @Query("SELECT COUNT(k) FROM KeyVersion k WHERE k.active = true")
    long countActiveKeys();
}