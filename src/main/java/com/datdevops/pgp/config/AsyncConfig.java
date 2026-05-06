package com.datdevops.pgp.config;

import com.datdevops.pgp.security.SenderContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskDecorator;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;

@Configuration
@EnableAsync
public class AsyncConfig implements AsyncConfigurer {

    @Override
    public Executor getAsyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(20);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("PgpAsync-");
        executor.setTaskDecorator(new ContextCopyingDecorator());
        executor.setRejectedExecutionHandler((r, executor1) -> {
            throw new org.springframework.core.task.TaskRejectedException("Async queue is full, please retry later");
        });
        executor.initialize();
        return executor;
    }

    /**
     * Decorator to propagate SenderContext (ThreadLocal) to worker threads.
     */
    static class ContextCopyingDecorator implements TaskDecorator {
        @Override
        public Runnable decorate(Runnable runnable) {
            SenderContext.Identity identity = SenderContext.getIdentity();
            return () -> {
                try {
                    if (identity != null) {
                        SenderContext.setIdentity(identity);
                    }
                    runnable.run();
                } finally {
                    SenderContext.clear();
                }
            };
        }
    }
}
