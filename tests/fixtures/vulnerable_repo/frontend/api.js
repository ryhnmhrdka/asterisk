// Developer Pre-Production API Client

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // CWE-295: Disabled TLS check

const API_BASE = "http://api.backend.kartikacyber.local/v1"; // CWE-319: Cleartext

const corsConfig = {
    origin: "*", // CWE-942: Permissive CORS Wildcard
    credentials: true
};

function executeUserCode(payload) {
    // CWE-95: Eval dynamic code
    return eval(payload);
}

module.exports = { API_BASE, corsConfig, executeUserCode };

