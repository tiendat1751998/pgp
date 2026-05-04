package com.datdevops.pgp.repository;

import com.datdevops.pgp.entity.KeyVersionInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface KeyVersionInfoRepository extends JpaRepository<KeyVersionInfo, String> {

    List<KeyVersionInfo> findByEntityIdOrderByCreatedAtDesc(String entityId);

    Optional<KeyVersionInfo> findByEntityIdAndKeyTypeAndActiveTrue(String entityId, String keyType);

    List<KeyVersionInfo> findByEntityIdAndKeyType(String entityId, String keyType);

    @Query("SELECT k FROM KeyVersionInfo k WHERE k.active = true")
    List<KeyVersionInfo> findAllActive();

    @Modifying
    @Query("UPDATE KeyVersionInfo k SET k.active = false WHERE k.entityId = :entityId AND k.keyType = :keyType AND k.active = true")
    int deactivatePreviousVersions(@Param("entityId") String entityId, @Param("keyType") String keyType);

    @Query("SELECT COUNT(k) FROM KeyVersionInfo k WHERE k.active = true")
    long countActiveKeys();
}