package com.datdevops.pgp.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "async_jobs")
public class AsyncJob {

    @Id
    private String jobId;

    @Column(nullable = false)
    private String jobType;

    @Column(nullable = false)
    private String status;

    private String entityId;
    private String keyType;
    private String result;
    private String errorMessage;

    @Column(nullable = false)
    private Instant createdAt;

    private Instant completedAt;

    public AsyncJob() {
        this.createdAt = Instant.now();
        this.status = "PENDING";
    }

    public AsyncJob(String jobId, String jobType, String entityId, String keyType) {
        this();
        this.jobId = jobId;
        this.jobType = jobType;
        this.entityId = entityId;
        this.keyType = keyType;
    }

    public String getJobId() { return jobId; }
    public void setJobId(String jobId) { this.jobId = jobId; }
    public String getJobType() { return jobType; }
    public void setJobType(String jobType) { this.jobType = jobType; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }
    public String getKeyType() { return keyType; }
    public void setKeyType(String keyType) { this.keyType = keyType; }
    public String getResult() { return result; }
    public void setResult(String result) { this.result = result; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }
}