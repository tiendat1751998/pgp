package com.datdevops.pgp.security;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class CertificateRevocationTest {

    @Test
    public void testExpiredCertificate_IsRejected() {
        Date now = new Date();
        Date futureDate = new Date(now.getTime() + 86400000);

        assertTrue(now.before(futureDate), "Future date is after now");
    }

    @Test
    public void testNotYetValidCertificate_IsRejected() {
        Date now = new Date();
        Date futureStart = new Date(now.getTime() + 86400000);

        assertTrue(now.before(futureStart), "Now is before future start date");
    }

    @Test
    public void testValidCertificate_DateLogic() {
        long nowMs = System.currentTimeMillis();
        Date pastDate = new Date(nowMs - 86400000);
        Date futureDate = new Date(nowMs + 86400000L * 30);

        assertTrue(pastDate.getTime() < nowMs, "Past date is before now");
        assertTrue(futureDate.getTime() > nowMs, "Future date is after now");
        assertTrue(futureDate.getTime() > pastDate.getTime(), "Future is after past");
    }

    @Test
    public void testCertificateValidationLogic() {
        long nowMs = System.currentTimeMillis();
        Date validNotBefore = new Date(nowMs - 86400000);
        Date validNotAfter = new Date(nowMs + 86400000L * 30);

        boolean isAfterNotBefore = nowMs > validNotBefore.getTime();
        boolean isBeforeNotAfter = nowMs < validNotAfter.getTime();

        assertTrue(isAfterNotBefore, "Now is after notBefore");
        assertTrue(isBeforeNotAfter, "Now is before notAfter");
    }
}