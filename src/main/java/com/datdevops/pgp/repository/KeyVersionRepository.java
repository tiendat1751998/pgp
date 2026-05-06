package com.datdevops.pgp.repository;

import com.datdevops.pgp.entity.KeyVersion;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface KeyVersionRepository extends JpaRepository<KeyVersion, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT k FROM KeyVersion k WHERE k.ownerId = :ownerId AND k.keyType = :keyType AND k.active = true ORDER BY k.version DESC LIMIT 1")
    Optional<KeyVersion> findActiveKeyForUpdate(@Param("ownerId") String ownerId, @Param("keyType") String keyType);

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

    @Modifying
    @Transactional
    @Query("UPDATE KeyVersion k SET k.active = false, k.rotatedAt = :now, k.validTo = :now WHERE k.ownerId = :ownerId AND k.keyType = :keyType AND k.active = true")
    int deactivateExistingKeys(@Param("ownerId") String ownerId, @Param("keyType") String keyType, @Param("now") Instant now);

    @Query("SELECT COUNT(k) FROM KeyVersion k WHERE k.active = true")
    long countActiveKeys();

    @Modifying
    @Transactional
    @Query("DELETE FROM KeyVersion k WHERE k.ownerId = :ownerId")
    void deleteByOwnerId(@Param("ownerId") String ownerId);
}