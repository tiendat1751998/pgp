import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  scenarios: {
    oom_attack: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'generateKey',
    },
    cpu_starvation: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 50 },
        { duration: '30s', target: 50 },
      ],
      exec: 'onboardPartner',
    },
  },
};

// Mock authentication context for tests
const params = {
  headers: {
    'Content-Type': 'application/json',
    'X-Mock-Sender': 'PARTNER_A', // Assuming a mock header for testing if mTLS is bypassed locally
  },
};

export function generateKey() {
  const payload = JSON.stringify({ keyType: 'RSA' });
  const res = http.post('http://localhost:8080/api/v1/crypto/keys/generate', payload, params);
  
  check(res, {
    'status is 202': (r) => r.status === 202,
  });
}

export function onboardPartner() {
  const payload = JSON.stringify({
    name: 'Attacker Partner',
    customerRsaPublicKey: 'MOCK_RSA_KEY',
    customerEd25519PublicKey: 'MOCK_ED_KEY'
  });
  
  const res = http.post('http://localhost:8080/api/v1/partners/onboard', payload, params);
  
  check(res, {
    'status is 200 or 400': (r) => r.status === 200 || r.status === 400,
    'latency < 2s': (r) => r.timings.duration < 2000,
  });
}
