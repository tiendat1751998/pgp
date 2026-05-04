package com.datdevops.pgp.repository;

import com.datdevops.pgp.entity.AsyncJob;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AsyncJobRepository extends JpaRepository<AsyncJob, String> {
    List<AsyncJob> findByStatusOrderByCreatedAtDesc(String status);
    List<AsyncJob> findByEntityIdOrderByCreatedAtDesc(String entityId);
}