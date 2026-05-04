package com.datdevops.pgp.dto.response;

public record AsyncJobResponse(
    String jobId,
    String status,
    String entityId,
    String keyType,
    Long createdAt,
    Long completedAt,
    Object result,
    String error,
    String message
) {
    public static AsyncJobResponse processing(String jobId, String entityId, String keyType) {
        return new AsyncJobResponse(jobId, "PROCESSING", entityId, keyType, 
            System.currentTimeMillis(), null, null, null,
            "Key generation started. Use /status/{jobId} to check progress.");
    }

    public static AsyncJobResponse fromEntity(com.datdevops.pgp.entity.AsyncJob job) {
        String error = "FAILED".equals(job.getStatus()) ? job.getErrorMessage() : null;
        return new AsyncJobResponse(
            job.getJobId(),
            job.getStatus(),
            job.getEntityId(),
            job.getKeyType(),
            job.getCreatedAt() != null ? job.getCreatedAt().toEpochMilli() : null,
            job.getCompletedAt() != null ? job.getCompletedAt().toEpochMilli() : null,
            "COMPLETED".equals(job.getStatus()) ? job.getResult() : null,
            error,
            null
        );
    }
}