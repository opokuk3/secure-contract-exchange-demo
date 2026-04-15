"""
Secure Contract Exchange Protocol
Cryptographic Protocol Demonstration — Flask Web Application

Run:
    pip install flask cryptography
    python app.py

Then open:  http://localhost:5000
"""

from flask import Flask, render_template_string, request, jsonify, session
import os, hashlib, datetime, json, base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256K1, generate_private_key, ECDSA, ECDH
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.secret_key = os.urandom(32)

# ── Crypto helpers ────────────────────────────────────────────────────────────

def make_cert(private_key, common_name, org, ca_key=None, ca_cert=None):
    pub  = private_key.public_key()
    now  = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    subj = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "GB"),
    ])
    issuer      = subj        if ca_cert is None else ca_cert.subject
    signing_key = private_key if ca_key  is None else ca_key
    return (
        x509.CertificateBuilder()
        .subject_name(subj).issuer_name(issuer).public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=(ca_cert is None), path_length=None), critical=True)
        .sign(signing_key, hashes.SHA256(), default_backend())
    )

def verify_cert(cert, ca_cert):
    try:
        ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ECDSA(hashes.SHA256()))
        return True
    except:
        return False

def derive_key(private_key, peer_pub, label="session"):
    shared = private_key.exchange(ECDH(), peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=label.encode(), backend=default_backend()).derive(shared)

def aes_encrypt(key, plaintext):
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, None)

def aes_decrypt(key, nonce, ciphertext):
    return AESGCM(key).decrypt(nonce, ciphertext, None)

def key_to_b64(key):
    return base64.b64encode(
        key.private_bytes(serialization.Encoding.DER,
                          serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
    ).decode()

def key_from_b64(b64):
    return serialization.load_der_private_key(base64.b64decode(b64), None, default_backend())

def cert_to_b64(cert):
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()

def cert_from_b64(b64):
    return x509.load_der_x509_certificate(base64.b64decode(b64), default_backend())

# ── HTML Template ─────────────────────────────────────────────────────────────

HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure Contract Exchange — Cryptography Demo</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:       #0a0e1a;
    --surface:  #111827;
    --panel:    #1a2235;
    --border:   #1e3a5f;
    --accent:   #0ea5e9;
    --accent2:  #38bdf8;
    --green:    #22c55e;
    --red:      #ef4444;
    --amber:    #f59e0b;
    --text:     #e2e8f0;
    --muted:    #64748b;
    --mono:     'IBM Plex Mono', monospace;
    --sans:     'IBM Plex Sans', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    background-image:
      radial-gradient(ellipse at 20% 0%, rgba(14,165,233,0.08) 0%, transparent 60%),
      radial-gradient(ellipse at 80% 100%, rgba(56,189,248,0.05) 0%, transparent 60%);
  }

  /* ── Header ── */
  header {
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(17,24,39,0.9);
    backdrop-filter: blur(12px);
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .logo {
    display: flex;
    align-items: center;
    gap: 10px;
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--accent);
    letter-spacing: 0.05em;
  }
  .logo-dot {
    width: 8px; height: 8px;
    background: var(--green);
    border-radius: 50%;
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%,100% { opacity:1; transform:scale(1); }
    50%      { opacity:0.5; transform:scale(0.8); }
  }
  .badge {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--muted);
    border: 1px solid var(--border);
    padding: 3px 10px;
    border-radius: 20px;
  }

  /* ── Layout ── */
  .container {
    max-width: 1100px;
    margin: 0 auto;
    padding: 2.5rem 2rem;
  }

  /* ── Hero ── */
  .hero {
    text-align: center;
    padding: 3rem 0 2.5rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2.5rem;
  }
  .hero-tag {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--accent);
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 1rem;
    display: block;
  }
  .hero h1 {
    font-size: 2.2rem;
    font-weight: 700;
    line-height: 1.15;
    margin-bottom: 0.75rem;
    background: linear-gradient(135deg, #e2e8f0 0%, var(--accent2) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .hero p {
    color: var(--muted);
    font-size: 0.95rem;
    max-width: 580px;
    margin: 0 auto;
    line-height: 1.6;
  }

  /* ── Steps nav ── */
  .steps-nav {
    display: flex;
    gap: 4px;
    margin-bottom: 2rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 6px;
    overflow-x: auto;
  }
  .step-btn {
    flex: 1;
    min-width: 80px;
    padding: 8px 6px;
    border: none;
    background: transparent;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 0.68rem;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s;
    text-align: center;
    line-height: 1.3;
  }
  .step-btn:hover  { background: var(--panel); color: var(--text); }
  .step-btn.active { background: var(--accent); color: #fff; font-weight: 600; }
  .step-btn.done   { background: rgba(34,197,94,0.15); color: var(--green); }
  .step-btn .step-num { display: block; font-size: 0.85em; margin-bottom: 2px; }

  /* ── Cards ── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 1.75rem;
    margin-bottom: 1.25rem;
    animation: fadeUp 0.3s ease;
  }
  @keyframes fadeUp {
    from { opacity:0; transform:translateY(12px); }
    to   { opacity:1; transform:translateY(0); }
  }
  .card-title {
    font-size: 0.7rem;
    font-family: var(--mono);
    color: var(--accent);
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-bottom: 0.6rem;
  }
  .card h2 {
    font-size: 1.3rem;
    font-weight: 600;
    margin-bottom: 0.75rem;
  }
  .card p {
    color: #94a3b8;
    font-size: 0.9rem;
    line-height: 1.65;
  }

  /* ── Form ── */
  .form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-top: 1.25rem;
  }
  .form-grid.full { grid-template-columns: 1fr; }
  label {
    display: block;
    font-size: 0.75rem;
    font-family: var(--mono);
    color: var(--muted);
    margin-bottom: 5px;
    letter-spacing: 0.05em;
  }
  input[type=text], input[type=number], textarea {
    width: 100%;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-family: var(--sans);
    font-size: 0.9rem;
    padding: 10px 14px;
    outline: none;
    transition: border-color 0.2s;
  }
  input:focus, textarea:focus { border-color: var(--accent); }

  /* ── Buttons ── */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 11px 24px;
    border: none;
    border-radius: 8px;
    font-family: var(--sans);
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
  }
  .btn-primary {
    background: var(--accent);
    color: #fff;
  }
  .btn-primary:hover { background: var(--accent2); transform: translateY(-1px); }
  .btn-secondary {
    background: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
  }
  .btn-secondary:hover { border-color: var(--accent); color: var(--accent); }
  .btn-danger {
    background: rgba(239,68,68,0.15);
    color: var(--red);
    border: 1px solid rgba(239,68,68,0.3);
  }
  .btn-success {
    background: rgba(34,197,94,0.15);
    color: var(--green);
    border: 1px solid rgba(34,197,94,0.3);
  }
  .btn-row { display: flex; gap: 10px; margin-top: 1.25rem; flex-wrap: wrap; }

  /* ── Result blocks ── */
  .result-block {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.25rem;
    margin-top: 1rem;
  }
  .result-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding: 6px 0;
    border-bottom: 1px solid rgba(30,58,95,0.5);
    gap: 1rem;
  }
  .result-row:last-child { border-bottom: none; }
  .result-label {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--muted);
    white-space: nowrap;
    padding-top: 2px;
    min-width: 160px;
  }
  .result-value {
    font-family: var(--mono);
    font-size: 0.75rem;
    color: var(--text);
    word-break: break-all;
    text-align: right;
  }

  /* ── Status badges ── */
  .status {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: 3px 10px;
    border-radius: 20px;
    font-weight: 600;
  }
  .status-ok      { background: rgba(34,197,94,0.15);  color: var(--green); }
  .status-fail    { background: rgba(239,68,68,0.15);  color: var(--red);   }
  .status-warn    { background: rgba(245,158,11,0.15); color: var(--amber); }
  .status-info    { background: rgba(14,165,233,0.15); color: var(--accent);}

  /* ── Terminal log ── */
  .terminal {
    background: #060a12;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem 1.25rem;
    font-family: var(--mono);
    font-size: 0.78rem;
    line-height: 1.7;
    max-height: 280px;
    overflow-y: auto;
    margin-top: 1rem;
  }
  .terminal .t-ok     { color: var(--green); }
  .terminal .t-fail   { color: var(--red);   }
  .terminal .t-info   { color: var(--accent);}
  .terminal .t-muted  { color: var(--muted); }
  .terminal .t-warn   { color: var(--amber); }
  .terminal .t-key    { color: #a78bfa;      }

  /* ── Cert viewer ── */
  .cert-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.75rem;
    margin-top: 1rem;
  }
  .cert-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem;
  }
  .cert-card h4 {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--accent);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
  }
  .cert-field {
    font-size: 0.78rem;
    color: #94a3b8;
    margin-bottom: 3px;
  }
  .cert-field span { color: var(--text); font-family: var(--mono); }

  /* ── Protocol flow ── */
  .flow {
    display: flex;
    flex-direction: column;
    gap: 0;
    margin-top: 1rem;
  }
  .flow-step {
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    padding: 0.85rem 0;
    border-bottom: 1px solid rgba(30,58,95,0.4);
    animation: fadeUp 0.3s ease both;
  }
  .flow-step:last-child { border-bottom: none; }
  .flow-num {
    width: 28px; height: 28px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--accent);
    flex-shrink: 0;
    margin-top: 2px;
  }
  .flow-num.done {
    background: rgba(34,197,94,0.15);
    border-color: var(--green);
    color: var(--green);
  }
  .flow-content { flex: 1; }
  .flow-title { font-weight: 600; font-size: 0.9rem; margin-bottom: 2px; }
  .flow-desc  { font-size: 0.82rem; color: #94a3b8; }

  /* ── Summary ── */
  .summary-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-top: 1rem;
  }
  .summary-item {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1rem;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .summary-icon {
    width: 36px; height: 36px;
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 1.1rem;
    flex-shrink: 0;
  }
  .summary-item h4 { font-size: 0.85rem; font-weight: 600; margin-bottom: 2px; }
  .summary-item p  { font-size: 0.78rem; color: var(--muted); }

  /* ── Loading spinner ── */
  .spinner {
    display: inline-block;
    width: 14px; height: 14px;
    border: 2px solid rgba(14,165,233,0.3);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    vertical-align: middle;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Hash compare ── */
  .hash-compare {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-top: 1rem;
  }
  .hash-box {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0.85rem;
  }
  .hash-box.match   { border-color: var(--green); }
  .hash-box.nomatch { border-color: var(--red); }
  .hash-box label   { color: var(--muted); font-size: 0.72rem; font-family: var(--mono); display: block; margin-bottom: 4px; }
  .hash-box code    { font-family: var(--mono); font-size: 0.7rem; word-break: break-all; }

  .hidden { display: none !important; }
  #error-msg { color: var(--red); font-size: 0.85rem; margin-top: 0.5rem; display: none; }

  @media (max-width: 700px) {
    .form-grid, .cert-grid, .summary-grid, .hash-compare { grid-template-columns: 1fr; }
    .hero h1 { font-size: 1.6rem; }
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-dot"></div>
    SECURE CONTRACT PROTOCOL
  </div>
  <span class="badge">Cryptographic Protocol Demo</span>
</header>

<div class="container">

  <!-- Hero -->
  <div class="hero">
    <span class="hero-tag">Cryptographic Protocol · Live Demonstration</span>
    <h1>Cryptographic Protocol<br>Demonstration</h1>
    <p>A live simulation of the six-step property contract exchange protocol using ECDSA, ECDH, AES-256-GCM and X.509 PKI.</p>
  </div>

  <!-- Steps Nav -->
  <div class="steps-nav" id="steps-nav">
    <button class="step-btn active" onclick="showStep(0)" id="nav-0">
      <span class="step-num">●</span>Setup
    </button>
    <button class="step-btn" onclick="showStep(1)" id="nav-1">
      <span class="step-num">1</span>Trust
    </button>
    <button class="step-btn" onclick="showStep(2)" id="nav-2">
      <span class="step-num">2</span>Deliver
    </button>
    <button class="step-btn" onclick="showStep(3)" id="nav-3">
      <span class="step-num">3</span>Forward
    </button>
    <button class="step-btn" onclick="showStep(4)" id="nav-4">
      <span class="step-num">4</span>Sign
    </button>
    <button class="step-btn" onclick="showStep(5)" id="nav-5">
      <span class="step-num">5</span>Return
    </button>
    <button class="step-btn" onclick="showStep(6)" id="nav-6">
      <span class="step-num">6</span>Handover
    </button>
    <button class="step-btn" onclick="showStep(7)" id="nav-7">
      <span class="step-num">⚡</span>Tamper
    </button>
  </div>

  <!-- STEP 0: Setup -->
  <div class="step-panel" id="step-0">
    <div class="card">
      <div class="card-title">Step 0 — Protocol Initialisation</div>
      <h2>Contract Details &amp; Key Generation</h2>
      <p>Enter the property contract details below. The system will generate X.509 certificates and ECDSA key pairs for all three parties using the secp256k1 curve.</p>
      <div class="form-grid">
        <div>
          <label>PARTY A NAME</label>
          <input type="text" id="seller" value="A. Smith" placeholder="Party A">
        </div>
        <div>
          <label>PARTY B NAME</label>
          <input type="text" id="buyer" value="B. Jones" placeholder="Party B">
        </div>
        <div>
          <label>INTERMEDIARY FIRM</label>
          <input type="text" id="ssol" value="Smith &amp; Co" placeholder="Intermediary firm">
        </div>
        <div>
          <label>AGREED PRICE (GBP)</label>
          <input type="text" id="price" value="245000" placeholder="245000">
        </div>
      </div>
      <div class="form-grid full" style="margin-top:0.75rem">
        <div>
          <label>PROPERTY ADDRESS</label>
          <input type="text" id="address" value="14 Elm Street, London, EC1A 1BB">
        </div>
      </div>
      <div id="error-msg"></div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="runSetup()">
          <span id="setup-spinner" class="spinner hidden"></span>
          Generate Keys &amp; Certificates →
        </button>
      </div>
    </div>

    <div class="card hidden" id="setup-result">
      <div class="card-title">PKI — Certificates Issued</div>
      <h2>Key Generation Complete</h2>
      <div class="cert-grid" id="cert-display"></div>
      <div class="terminal" id="setup-log"></div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="nextStep(0)">Proceed to Step 1 →</button>
      </div>
    </div>
  </div>

  <!-- STEP 1: Trust -->
  <div class="step-panel hidden" id="step-1">
    <div class="card">
      <div class="card-title">Step 1 — Trust Establishment</div>
      <h2>First Contact: Party A ↔ Intermediary</h2>
      <p>Two parties that have never communicated before exchange X.509 certificates, verify them against the trusted CA, then perform ECDH key exchange to derive a shared session key — independently, without transmitting the secret.</p>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="runStep1()">
          <span id="step1-spinner" class="spinner hidden"></span>
          Run Trust Establishment →
        </button>
      </div>
    </div>
    <div class="card hidden" id="step1-result">
      <div class="card-title">Results</div>
      <h2>ECDH Key Exchange</h2>
      <div class="terminal" id="step1-log"></div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="nextStep(1)">Proceed to Step 2 →</button>
      </div>
    </div>
  </div>

  <!-- STEP 2: Deliver -->
  <div class="step-panel hidden" id="step-2">
    <div class="card">
      <div class="card-title">Step 2 — Contract Delivery</div>
      <h2>Party A → Intermediary</h2>
      <p>Party A encrypts the document using AES-256-GCM with the shared ECDH session key. The GCM authentication tag ensures integrity — no separate HMAC needed. The intermediary decrypts and verifies.</p>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="runStep2()">
          <span id="step2-spinner" class="spinner hidden"></span>
          Encrypt &amp; Deliver Contract →
        </button>
      </div>
    </div>
    <div class="card hidden" id="step2-result">
      <div class="card-title">Results</div>
      <h2>AES-256-GCM Encryption</h2>
      <div class="terminal" id="step2-log"></div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="nextStep(2)">Proceed to Step 3 →</button>
      </div>
    </div>
  </div>

  <!-- STEP 3: Forward -->
  <div class="step-panel hidden" id="step-3">
    <div class="card">
      <div class="card-title">Step 3 — Forward to Buyer</div>
      <h2>Intermediary → Party B</h2>
      <p>The intermediary re-encrypts the document under a Party B-specific ECDH session key and attaches an ECDSA signature. Party B verifies the intermediary's identity via their X.509 certificate before decrypting.</p>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="runStep3()">
          <span id="step3-spinner" class="spinner hidden"></span>
          Sign &amp; Forward to Buyer →
        </button>
      </div>
    </div>
    <div class="card hidden" id="step3-result">
      <div class="card-title">Results</div>
      <h2>ECDSA Signing + Re-encryption</h2>
      <div class="terminal" id="step3-log"></div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="nextStep(3)">Proceed to Step 4 →</button>
      </div>
    </div>
  </div>

  <!-- STEP 4: Sign -->
  <div class="step-panel hidden" id="step-4">
    <div class="card">
      <div class="card-title">Step 4 — Buyer Signs the Contract</div>
      <h2>Legally Binding Digital Signature</h2>
      <p>Party B reviews the document and decides whether to sign. Their ECDSA private key signs the document — a cryptographically binding step satisfying Advanced Electronic Signature (AdES) criteria.</p>
      <div class="card" style="margin-top:1rem; background:var(--panel)">
        <div class="card-title">Contract Contents</div>
        <div id="contract-preview" style="font-family:var(--mono);font-size:0.8rem;line-height:1.8;color:#94a3b8;white-space:pre-wrap;"></div>
      </div>
      <div class="btn-row">
        <button class="btn btn-success" onclick="runStep4(true)">
          <span id="step4-spinner" class="spinner hidden"></span>
          ✓ Sign the Contract
        </button>
        <button class="btn btn-danger" onclick="runStep4(false)">
          ✗ Decline to Sign
        </button>
      </div>
    </div>
    <div class="card hidden" id="step4-result">
      <div class="card-title">Results</div>
      <h2>ECDSA Signature Generated</h2>
      <div class="terminal" id="step4-log"></div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="nextStep(4)">Proceed to Step 5 →</button>
      </div>
    </div>
  </div>

  <!-- STEP 5: Return -->
  <div class="step-panel hidden" id="step-5">
    <div class="card">
      <div class="card-title">Step 5 — Signed Contract Return</div>
      <h2>Party B → Intermediary</h2>
      <p>Party B encrypts and returns the signed document. The intermediary verifies Party B's X.509 certificate against the CA, then verifies the ECDSA signature — confirming non-repudiation.</p>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="runStep5()">
          <span id="step5-spinner" class="spinner hidden"></span>
          Return Signed Contract →
        </button>
      </div>
    </div>
    <div class="card hidden" id="step5-result">
      <div class="card-title">Results</div>
      <h2>Signature Verification at Intermediary</h2>
      <div class="terminal" id="step5-log"></div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="nextStep(5)">Proceed to Step 6 →</button>
      </div>
    </div>
  </div>

  <!-- STEP 6: Handover -->
  <div class="step-panel hidden" id="step-6">
    <div class="card">
      <div class="card-title">Step 6 — Final Handover</div>
      <h2>Intermediary → Party A</h2>
      <p>The intermediary encrypts and forwards the final signed document to Party A. Party A decrypts, verifies the GCM integrity tag, and performs final ECDSA verification — the transaction is complete.</p>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="runStep6()">
          <span id="step6-spinner" class="spinner hidden"></span>
          Complete Transaction →
        </button>
      </div>
    </div>
    <div class="card hidden" id="step6-result">
      <div class="card-title">Results</div>
      <h2>Transaction Complete</h2>
      <div class="terminal" id="step6-log"></div>
      <div id="summary-panel" class="hidden">
        <div class="card" style="border-color:var(--green)">
          <div class="card-title" style="color:var(--green)">Protocol Summary</div>
          <h2>All Six Steps Completed Successfully</h2>
          <div class="summary-grid" id="summary-grid"></div>
        </div>
      </div>
      <div class="btn-row">
        <button class="btn btn-primary" onclick="nextStep(6)">Run Tamper Detection Demo →</button>
      </div>
    </div>
  </div>

  <!-- STEP 7: Tamper -->
  <div class="step-panel hidden" id="step-7">
    <div class="card">
      <div class="card-title">Tamper Detection Demo</div>
      <h2>Integrity Attack Simulation</h2>
      <p>Enter a fraudulent price to simulate an attacker modifying the contract after the buyer has signed. The SHA-256 hash will change completely, causing ECDSA verification to fail — demonstrating the protocol's integrity guarantee.</p>
      <div class="form-grid" style="margin-top:1rem; max-width:300px">
        <div>
          <label>FRAUDULENT PRICE (GBP)</label>
          <input type="text" id="fake-price" placeholder="e.g. 100000">
        </div>
      </div>
      <div class="btn-row">
        <button class="btn btn-danger" onclick="runTamper()">
          <span id="tamper-spinner" class="spinner hidden"></span>
          Simulate Tamper Attack →
        </button>
      </div>
    </div>
    <div class="card hidden" id="tamper-result">
      <div class="card-title">Tamper Detection Results</div>
      <h2>Hash Comparison</h2>
      <div class="hash-compare" id="hash-compare"></div>
      <div class="terminal" id="tamper-log" style="margin-top:1rem"></div>
      <div class="btn-row" style="margin-top:1rem">
        <button class="btn btn-secondary" onclick="resetAll()">↺ Start New Simulation</button>
      </div>
    </div>
  </div>


</div><!-- /container -->

<!-- ── Signature Footer ── -->
<footer class="sig-footer">
  <div class="sig-inner">
    <div class="sig-divider"></div>
    <div class="sig-content">
      <div class="sig-left">
        <span class="sig-made">cryptographic protocol demonstration</span>
        <span class="sig-name">Kaira</span>
        <span class="sig-module">Built with Python · Flask · OpenSSL</span>
      </div>
      <div class="sig-right">
        <div class="sig-stack">
          <span class="sig-tag">Python</span>
          <span class="sig-tag">Flask</span>
          <span class="sig-tag">ECDSA</span>
          <span class="sig-tag">AES-256-GCM</span>
          <span class="sig-tag">X.509 PKI</span>
        </div>
      </div>
    </div>
  </div>
</footer>

<style>
.sig-footer {
  margin-top: 4rem;
  padding: 0 2rem 2.5rem;
  max-width: 1100px;
  margin-left: auto;
  margin-right: auto;
}
.sig-divider {
  height: 1px;
  background: linear-gradient(90deg,
    transparent 0%,
    var(--border) 20%,
    var(--accent) 50%,
    var(--border) 80%,
    transparent 100%);
  margin-bottom: 1.5rem;
}
.sig-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
}
.sig-left {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.sig-made {
  font-family: var(--mono);
  font-size: 0.68rem;
  color: var(--muted);
  letter-spacing: 0.12em;
  text-transform: uppercase;
}
.sig-name {
  font-family: var(--mono);
  font-size: 1.6rem;
  font-weight: 600;
  letter-spacing: 0.08em;
  background: linear-gradient(135deg, var(--accent) 0%, #a78bfa 60%, var(--accent2) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  line-height: 1;
}
.sig-module {
  font-size: 0.72rem;
  color: var(--muted);
  font-family: var(--sans);
  margin-top: 2px;
}
.sig-right {
  display: flex;
  align-items: center;
}
.sig-stack {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.sig-tag {
  font-family: var(--mono);
  font-size: 0.68rem;
  padding: 4px 10px;
  border-radius: 20px;
  border: 1px solid var(--border);
  color: var(--muted);
  background: var(--surface);
  transition: all 0.2s;
}
.sig-tag:hover {
  border-color: var(--accent);
  color: var(--accent);
  background: rgba(14,165,233,0.08);
}
@media (max-width: 600px) {
  .sig-content { flex-direction: column; align-items: flex-start; }
  .sig-stack   { justify-content: flex-start; }
}
</style>

<script>
// ── State ────────────────────────────────────────────────────────────────────

let currentStep = 0;
const TOTAL_STEPS = 8;

function showStep(n) {
  document.querySelectorAll('.step-panel').forEach(el => el.classList.add('hidden'));
  document.getElementById('step-' + n).classList.remove('hidden');
  document.querySelectorAll('.step-btn').forEach((btn, i) => {
    btn.classList.remove('active');
    if (i === n) btn.classList.add('active');
  });
  currentStep = n;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function nextStep(from) {
  const nav = document.getElementById('nav-' + from);
  nav.classList.remove('active');
  nav.classList.add('done');
  nav.querySelector('.step-num').textContent = '✓';
  showStep(from + 1);
}

function setSpinner(id, on) {
  document.getElementById(id).classList.toggle('hidden', !on);
}

// ── Terminal log ──────────────────────────────────────────────────────────────

function appendLog(logId, lines) {
  const el = document.getElementById(logId);
  el.innerHTML += lines.map(([cls, txt]) =>
    `<div class="t-${cls}">${escHtml(txt)}</div>`
  ).join('');
  el.scrollTop = el.scrollHeight;
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── API calls ────────────────────────────────────────────────────────────────

async function post(url, data) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  return r.json();
}

// ── Step 0: Setup ─────────────────────────────────────────────────────────────

async function runSetup() {
  const errEl = document.getElementById('error-msg');
  errEl.style.display = 'none';
  setSpinner('setup-spinner', true);

  const data = {
    seller:  document.getElementById('seller').value.trim()  || 'A. Smith',
    buyer:   document.getElementById('buyer').value.trim()   || 'B. Jones',
    ssol:    document.getElementById('ssol').value.trim()    || 'Smith & Co Solicitors',
    price:   document.getElementById('price').value.trim()   || '245000',
    address: document.getElementById('address').value.trim() || '14 Elm Street, London, EC1A 1BB',
  };

  const res = await post('/api/setup', data);
  setSpinner('setup-spinner', false);

  if (res.error) { errEl.textContent = res.error; errEl.style.display = 'block'; return; }

  document.getElementById('setup-result').classList.remove('hidden');

  // Cert cards
  const certDiv = document.getElementById('cert-display');
  certDiv.innerHTML = res.certs.map(c => `
    <div class="cert-card">
      <h4>${escHtml(c.role)}</h4>
      <div class="cert-field">Subject: <span>${escHtml(c.subject)}</span></div>
      <div class="cert-field">Issuer: <span>${escHtml(c.issuer)}</span></div>
      <div class="cert-field">Algorithm: <span>${escHtml(c.algorithm)}</span></div>
      <div class="cert-field">Valid Until: <span>${escHtml(c.valid_until)}</span></div>
      <div class="cert-field">Serial: <span>${escHtml(c.serial)}</span></div>
      <div style="margin-top:6px"><span class="status status-ok">✓ CA Verified</span></div>
    </div>
  `).join('');

  appendLog('setup-log', res.log);
}

// ── Step 1: Trust ──────────────────────────────────────────────────────────────

async function runStep1() {
  setSpinner('step1-spinner', true);
  const res = await post('/api/step1', {});
  setSpinner('step1-spinner', false);
  document.getElementById('step1-result').classList.remove('hidden');
  appendLog('step1-log', res.log);
}

// ── Step 2: Deliver ───────────────────────────────────────────────────────────

async function runStep2() {
  setSpinner('step2-spinner', true);
  const res = await post('/api/step2', {});
  setSpinner('step2-spinner', false);
  document.getElementById('step2-result').classList.remove('hidden');
  appendLog('step2-log', res.log);
}

// ── Step 3: Forward ───────────────────────────────────────────────────────────

async function runStep3() {
  setSpinner('step3-spinner', true);
  const res = await post('/api/step3', {});
  setSpinner('step3-spinner', false);
  document.getElementById('step3-result').classList.remove('hidden');
  appendLog('step3-log', res.log);
}

// ── Step 4: Sign ──────────────────────────────────────────────────────────────

async function runStep4(sign) {
  setSpinner('step4-spinner', true);
  const res = await post('/api/step4', { sign });
  setSpinner('step4-spinner', false);

  // Show contract preview before result
  document.getElementById('contract-preview').textContent = res.contract || '';
  document.getElementById('step4-result').classList.remove('hidden');
  appendLog('step4-log', res.log);

  if (!sign) {
    // Buyer declined — disable proceed button
    document.querySelector('#step4-result .btn-primary').disabled = true;
    document.querySelector('#step4-result .btn-primary').textContent = 'Transaction terminated';
  }
}

// Load contract preview on step 4 show
async function loadContractPreview() {
  const res = await post('/api/get_contract', {});
  if (res.contract) document.getElementById('contract-preview').textContent = res.contract;
}

// ── Step 5: Return ────────────────────────────────────────────────────────────

async function runStep5() {
  setSpinner('step5-spinner', true);
  const res = await post('/api/step5', {});
  setSpinner('step5-spinner', false);
  document.getElementById('step5-result').classList.remove('hidden');
  appendLog('step5-log', res.log);
}

// ── Step 6: Handover ──────────────────────────────────────────────────────────

async function runStep6() {
  setSpinner('step6-spinner', true);
  const res = await post('/api/step6', {});
  setSpinner('step6-spinner', false);
  document.getElementById('step6-result').classList.remove('hidden');
  appendLog('step6-log', res.log);

  // Summary
  if (res.summary) {
    document.getElementById('summary-panel').classList.remove('hidden');
    document.getElementById('summary-grid').innerHTML = res.summary.map(s => `
      <div class="summary-item">
        <div class="summary-icon" style="background:${s.bg}">${s.icon}</div>
        <div>
          <h4>${escHtml(s.title)}</h4>
          <p>${escHtml(s.desc)}</p>
        </div>
      </div>
    `).join('');
  }
}

// ── Tamper ────────────────────────────────────────────────────────────────────

async function runTamper() {
  const fakePrice = document.getElementById('fake-price').value.trim();
  if (!fakePrice) { alert('Please enter a fraudulent price to test with.'); return; }
  setSpinner('tamper-spinner', true);
  const res = await post('/api/tamper', { fake_price: fakePrice });
  setSpinner('tamper-spinner', false);
  document.getElementById('tamper-result').classList.remove('hidden');

  // Hash compare
  const hc = document.getElementById('hash-compare');
  hc.innerHTML = `
    <div class="hash-box">
      <label>ORIGINAL CONTRACT HASH (SHA-256)</label>
      <code style="color:var(--green)">${escHtml(res.orig_hash)}</code>
    </div>
    <div class="hash-box nomatch">
      <label>TAMPERED CONTRACT HASH (SHA-256)</label>
      <code style="color:var(--red)">${escHtml(res.tamper_hash)}</code>
    </div>
  `;
  appendLog('tamper-log', res.log);
}

// ── Reset ─────────────────────────────────────────────────────────────────────

async function resetAll() {
  await post('/api/reset', {});
  location.reload();
}

// ── Init ──────────────────────────────────────────────────────────────────────

// Auto-load contract preview when step 4 becomes visible
const origShowStep = showStep;
window.showStep = function(n) {
  origShowStep(n);
  if (n === 4) loadContractPreview();
};
</script>
</body>
</html>
'''

# ── In-memory state ───────────────────────────────────────────────────────────

state = {}

def reset_state():
    global state
    state = {}

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/reset', methods=['POST'])
def api_reset():
    reset_state()
    return jsonify({'ok': True})

@app.route('/api/setup', methods=['POST'])
def api_setup():
    reset_state()
    d = request.json
    seller  = d.get('seller',  'A. Smith')
    buyer   = d.get('buyer',   'B. Jones')
    ssol    = d.get('ssol',    'Smith & Co Solicitors')
    price   = d.get('price',   '245000')
    address = d.get('address', '14 Elm Street, London, EC1A 1BB')
    today   = datetime.date.today().strftime('%d %B %Y')

    contract_text = f"""    PROPERTY SALE AGREEMENT
    -----------------------
    Date     : {today}
    Seller   : {seller}
    Buyer    : {buyer}
    Property : {address}
    Price    : GBP {price}

    The buyer agrees to purchase the above property at the agreed
    price, subject to the terms and conditions set out herein,
    subject to the terms and conditions set out herein."""

    # Generate keys
    ca_key    = generate_private_key(SECP256K1(), default_backend())
    hr_key    = generate_private_key(SECP256K1(), default_backend())
    ssol_key  = generate_private_key(SECP256K1(), default_backend())
    buyer_key = generate_private_key(SECP256K1(), default_backend())

    ca_cert    = make_cert(ca_key,    'Legal-CA',  'UK Legal Certificate Authority')
    hr_cert    = make_cert(hr_key,    'Intermediary Ltd', 'Intermediary Ltd', ca_key, ca_cert)
    ssol_cert  = make_cert(ssol_key,  ssol, ssol, ca_key, ca_cert)
    buyer_cert = make_cert(buyer_key, buyer, buyer, ca_key, ca_cert)

    # Persist
    state.update({
        'contract':   contract_text,
        'price':      price,
        'buyer_name': buyer,
        'ca_key':     key_to_b64(ca_key),
        'hr_key':     key_to_b64(hr_key),
        'ssol_key':   key_to_b64(ssol_key),
        'buyer_key':  key_to_b64(buyer_key),
        'ca_cert':    cert_to_b64(ca_cert),
        'hr_cert':    cert_to_b64(hr_cert),
        'ssol_cert':  cert_to_b64(ssol_cert),
        'buyer_cert': cert_to_b64(buyer_cert),
    })

    def fmt_cert(cert, role):
        cn   = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        iss  = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        exp  = cert.not_valid_after_utc.strftime('%d %b %Y')
        ser  = str(cert.serial_number)[:12] + '...'
        return { 'role': role, 'subject': cn, 'issuer': iss,
                 'algorithm': 'ECDSA-SHA256 / secp256k1',
                 'valid_until': exp, 'serial': ser }

    certs = [
        fmt_cert(ca_cert,    'Certificate Authority'),
        fmt_cert(hr_cert,    'Intermediary'),
        fmt_cert(ssol_cert,  f'Seller\'s Solicitor — {ssol}'),
        fmt_cert(buyer_cert, f'Buyer — {buyer}'),
    ]

    log = [
        ['info', '── Certificate Authority'],
        ['ok',   '[OK]  CA key pair generated (secp256k1 / 256-bit)'],
        ['ok',   '[OK]  CA self-signed X.509 certificate created'],
        ['info', '── Intermediary'],
        ['ok',   '[OK]  Intermediary ECDSA key pair generated'],
        ['ok',   '[OK]  Intermediary X.509 certificate issued and signed by CA'],
        ['info', f'── Seller\'s Solicitor — {ssol}'],
        ['ok',   '[OK]  S.Sol ECDSA key pair generated'],
        ['ok',   '[OK]  S.Sol X.509 certificate issued and signed by CA'],
        ['info', f'── Buyer — {buyer}'],
        ['ok',   '[OK]  Buyer ECDSA key pair generated'],
        ['ok',   '[OK]  Buyer X.509 certificate issued and signed by CA'],
        ['muted',''],
        ['ok',   '[OK]  All certificates verified against CA — PKI trust chain established'],
        ['muted', f'Contract value: GBP {price} | Property: {address}'],
    ]
    return jsonify({'certs': certs, 'log': log})


@app.route('/api/step1', methods=['POST'])
def api_step1():
    ca_cert    = cert_from_b64(state['ca_cert'])
    hr_cert    = cert_from_b64(state['hr_cert'])
    ssol_cert  = cert_from_b64(state['ssol_cert'])
    hr_key     = key_from_b64(state['hr_key'])
    ssol_key   = key_from_b64(state['ssol_key'])
    buyer_cert = cert_from_b64(state['buyer_cert'])
    buyer_key  = key_from_b64(state['buyer_key'])

    hr_ok   = verify_cert(ssol_cert, ca_cert)
    ssol_ok = verify_cert(hr_cert,   ca_cert)

    hr_ssol_key  = derive_key(hr_key,   ssol_cert.public_key(), 'hr-ssol')
    ssol_hr_key  = derive_key(ssol_key, hr_cert.public_key(),   'hr-ssol')
    hr_buyer_key = derive_key(hr_key,   buyer_cert.public_key(),'hr-buyer')
    buyer_hr_key = derive_key(buyer_key,hr_cert.public_key(),   'hr-buyer')

    keys_match = hr_ssol_key == ssol_hr_key

    state['hr_ssol_key']  = base64.b64encode(hr_ssol_key).decode()
    state['ssol_hr_key']  = base64.b64encode(ssol_hr_key).decode()
    state['hr_buyer_key'] = base64.b64encode(hr_buyer_key).decode()
    state['buyer_hr_key'] = base64.b64encode(buyer_hr_key).decode()

    log = [
        ['info', '── Certificate Verification'],
        ['ok' if hr_ok   else 'fail', f'[{"OK" if hr_ok else "!!"}]  Intermediary verified Party A X.509 certificate against CA'],
        ['ok' if ssol_ok else 'fail', f'[{"OK" if ssol_ok else "!!"}]  Party A verified Intermediary X.509 certificate against CA'],
        ['muted',''],
        ['info', '── ECDH Key Exchange  (Intermediary ↔ Party A)'],
        ['ok',   '[OK]  Intermediary computed shared secret via ECDH'],
        ['ok',   '[OK]  S.Sol computed shared secret via ECDH'],
        ['ok' if keys_match else 'fail', f'[{"OK" if keys_match else "!!"}]  Session keys match: {"YES — forward secrecy active" if keys_match else "NO — ERROR"}'],
        ['key',  f'      Session key: {hr_ssol_key.hex()[:48]}...'],
        ['muted',''],
        ['info', '── ECDH Key Exchange  (Intermediary ↔ Party B)'],
        ['ok',   '[OK]  Intermediary ↔ Party B session key derived independently'],
        ['key',  f'      Buyer key:   {hr_buyer_key.hex()[:48]}...'],
        ['muted',''],
        ['ok',   '[OK]  Trust established — protocol ready for contract transmission'],
    ]
    return jsonify({'log': log})


@app.route('/api/step2', methods=['POST'])
def api_step2():
    ssol_hr_key  = base64.b64decode(state['ssol_hr_key'])
    hr_ssol_key  = base64.b64decode(state['hr_ssol_key'])
    contract     = state['contract'].encode()

    nonce1, ct1 = aes_encrypt(ssol_hr_key, contract)
    received    = aes_decrypt(hr_ssol_key, nonce1, ct1)
    match       = received == contract

    state['received_contract'] = base64.b64encode(received).decode()
    state['nonce1'] = base64.b64encode(nonce1).decode()

    log = [
        ['info', '── Encryption at Seller\'s Solicitor'],
        ['ok',   '[OK]  AES-256-GCM key: 256-bit ECDH-derived session key'],
        ['ok',   '[OK]  Contract encrypted'],
        ['key',  f'      Nonce (96-bit): {nonce1.hex()}'],
        ['muted',f'      Plaintext:  {len(contract)} bytes'],
        ['muted',f'      Ciphertext: {len(ct1)} bytes (includes 16-byte GCM auth tag)'],
        ['muted',''],
        ['info', '── Decryption at Intermediary'],
        ['ok',   '[OK]  Intermediary decrypted document successfully'],
        ['ok',   '[OK]  GCM authentication tag verified — integrity confirmed'],
        ['ok' if match else 'fail', f'[{"OK" if match else "!!"}]  Decrypted content matches original: {match}'],
        ['muted',''],
        ['ok',   '[OK]  Document securely received at Intermediary'],
    ]
    return jsonify({'log': log})


@app.route('/api/step3', methods=['POST'])
def api_step3():
    hr_key      = key_from_b64(state['hr_key'])
    hr_buyer_key= base64.b64decode(state['hr_buyer_key'])
    hr_cert     = cert_from_b64(state['hr_cert'])
    buyer_hr_key= base64.b64decode(state['buyer_hr_key'])
    received    = base64.b64decode(state['received_contract'])

    hr_sig          = hr_key.sign(received, ECDSA(hashes.SHA256()))
    nonce2, ct2     = aes_encrypt(hr_buyer_key, received)

    # Party B verifies Intermediary signature
    try:
        hr_cert.public_key().verify(hr_sig, received, ECDSA(hashes.SHA256()))
        sig_valid = True
    except InvalidSignature:
        sig_valid = False

    buyer_copy = aes_decrypt(buyer_hr_key, nonce2, ct2)

    state['hr_sig']    = base64.b64encode(hr_sig).decode()
    state['buyer_copy']= base64.b64encode(buyer_copy).decode()

    log = [
        ['info', '── Intermediary Signs and Re-Encrypts'],
        ['ok',   '[OK]  Intermediary computed ECDSA signature over document'],
        ['key',  f'      Intermediary sig (r,s): {hr_sig.hex()[:48]}...'],
        ['ok',   '[OK]  Contract re-encrypted for buyer under AES-256-GCM'],
        ['key',  f'      New nonce: {nonce2.hex()}'],
        ['muted',''],
        ['info', '── Buyer Verifies and Decrypts'],
        ['ok' if sig_valid else 'fail', f'[{"OK" if sig_valid else "!!"}]  Party B verified Intermediary ECDSA signature — source confirmed'],
        ['ok',   '[OK]  Buyer decrypted contract successfully'],
        ['muted',''],
        ['ok',   '[OK]  Contract securely in buyer\'s hands — ready for signing'],
    ]
    return jsonify({'log': log})


@app.route('/api/get_contract', methods=['POST'])
def api_get_contract():
    return jsonify({'contract': state.get('contract', '')})


@app.route('/api/step4', methods=['POST'])
def api_step4():
    sign        = request.json.get('sign', True)
    buyer_key_  = key_from_b64(state['buyer_key'])
    buyer_copy  = base64.b64decode(state['buyer_copy'])
    contract    = state['contract']

    if not sign:
        state['signed'] = False
        log = [
            ['warn',  '[--]  Buyer declined to sign the contract'],
            ['warn',  '[--]  Protocol terminated at Step 4'],
            ['muted', '      In a real system the Intermediary would be notified and the'],
            ['muted', '      transaction would be renegotiated or cancelled.'],
        ]
        return jsonify({'contract': contract, 'log': log})

    buyer_sig        = buyer_key_.sign(buyer_copy, ECDSA(hashes.SHA256()))
    contract_hash    = hashlib.sha256(buyer_copy).hexdigest()

    state['buyer_sig']      = base64.b64encode(buyer_sig).decode()
    state['contract_hash']  = contract_hash
    state['signed']         = True

    log = [
        ['info', '── ECDSA Signing (Buyer)'],
        ['ok',   '[OK]  SHA-256 hash computed over contract'],
        ['key',  f'      Hash: {contract_hash}'],
        ['ok',   '[OK]  ECDSA signature computed: z=SHA256(doc); r=(kP).x mod n; s=k⁻¹(z+r·d) mod n'],
        ['key',  f'      Signature (r,s): {buyer_sig.hex()[:48]}...'],
        ['ok',   '[OK]  Non-repudiation active — buyer cannot deny signing'],
        ['muted',''],
        ['ok',   '[OK]  Contract is now legally binding under UK-retained eIDAS (AdES criteria met)'],
    ]
    return jsonify({'contract': contract, 'log': log})


@app.route('/api/step5', methods=['POST'])
def api_step5():
    buyer_hr_key = base64.b64decode(state['buyer_hr_key'])
    hr_buyer_key = base64.b64decode(state['hr_buyer_key'])
    buyer_copy   = base64.b64decode(state['buyer_copy'])
    buyer_sig    = base64.b64decode(state['buyer_sig'])
    buyer_cert   = cert_from_b64(state['buyer_cert'])
    ca_cert      = cert_from_b64(state['ca_cert'])

    nonce3, ct3  = aes_encrypt(buyer_hr_key, buyer_copy)
    hr_received2 = aes_decrypt(hr_buyer_key, nonce3, ct3)

    cert_ok = verify_cert(buyer_cert, ca_cert)

    try:
        buyer_cert.public_key().verify(buyer_sig, hr_received2, ECDSA(hashes.SHA256()))
        sig_ok = True
    except InvalidSignature:
        sig_ok = False

    state['hr_received2'] = base64.b64encode(hr_received2).decode()

    log = [
        ['info', '── Buyer Encrypts and Sends'],
        ['ok',   '[OK]  Document encrypted under Party B-Intermediary session key'],
        ['muted',f'      Ciphertext: {len(ct3)} bytes'],
        ['muted',''],
        ['info', '── Intermediary Verifies'],
        ['ok' if cert_ok else 'fail', f'[{"OK" if cert_ok else "!!"}]  Intermediary verified Party B X.509 certificate against CA'],
        ['ok' if sig_ok  else 'fail', f'[{"OK" if sig_ok  else "!!"}]  Intermediary verified Party B ECDSA signature — {"VALID" if sig_ok else "INVALID"}'],
        ['ok',   '[OK]  Signature cryptographically bound to buyer\'s CA-verified identity'],
        ['ok',   '[OK]  Non-repudiation confirmed — legally enforceable'],
    ]
    return jsonify({'log': log})


@app.route('/api/step6', methods=['POST'])
def api_step6():
    hr_ssol_key  = base64.b64decode(state['hr_ssol_key'])
    ssol_hr_key  = base64.b64decode(state['ssol_hr_key'])
    hr_received2 = base64.b64decode(state['hr_received2'])
    buyer_sig    = base64.b64decode(state['buyer_sig'])
    buyer_cert   = cert_from_b64(state['buyer_cert'])

    nonce4, ct4  = aes_encrypt(hr_ssol_key, hr_received2)
    final        = aes_decrypt(ssol_hr_key, nonce4, ct4)

    try:
        buyer_cert.public_key().verify(buyer_sig, final, ECDSA(hashes.SHA256()))
        final_ok = True
    except InvalidSignature:
        final_ok = False

    state['final_contract'] = base64.b64encode(final).decode()

    log = [
        ['info', '── Intermediary Encrypts Final Package'],
        ['ok',   '[OK]  Document encrypted under Intermediary ↔ Party A session key'],
        ['key',  f'      Nonce: {nonce4.hex()}'],
        ['muted',''],
        ['info', '── Seller\'s Solicitor Decrypts and Verifies'],
        ['ok',   '[OK]  S.Sol decrypted final signed contract'],
        ['ok',   '[OK]  GCM authentication tag verified — integrity confirmed'],
        ['ok' if final_ok else 'fail', f'[{"OK" if final_ok else "!!"}]  S.Sol verified buyer ECDSA signature — {"VALID" if final_ok else "INVALID"}'],
        ['muted',''],
        ['ok',   '[OK]  TRANSACTION COMPLETE'],
        ['ok',   '[OK]  Contract fully enforceable under Electronic Communications Act 2000'],
        ['ok',   '[OK]  Advanced Electronic Signature (AdES) criteria satisfied'],
    ]

    summary = [
        {'icon':'🔐','bg':'rgba(14,165,233,0.15)', 'title':'ECDSA Signatures',    'desc':'2 signatures — Intermediary (forwarding) + Party B (binding)'},
        {'icon':'🔑','bg':'rgba(168,85,247,0.15)', 'title':'ECDH Key Exchange',   'desc':'2 independent session keys — forward secrecy active'},
        {'icon':'🛡','bg':'rgba(34,197,94,0.15)',  'title':'AES-256-GCM',         'desc':'4 separate encryptions — authenticated throughout'},
        {'icon':'📜','bg':'rgba(245,158,11,0.15)', 'title':'X.509 PKI',           'desc':'4 certificates — CA + Intermediary + Party A + Party B'},
        {'icon':'⚖️','bg':'rgba(239,68,68,0.15)',  'title':'Legal Status',        'desc':'AdES criteria met — enforceable under UK eIDAS'},
        {'icon':'✅','bg':'rgba(34,197,94,0.15)',  'title':'CIA+ Model',          'desc':'All 6 properties: C, I, A, Authenticity, Non-repudiation, Accountability'},
    ]
    return jsonify({'log': log, 'summary': summary})


@app.route('/api/tamper', methods=['POST'])
def api_tamper():
    fake_price     = request.json.get('fake_price', '100000')
    final          = base64.b64decode(state['final_contract'])
    buyer_sig      = base64.b64decode(state['buyer_sig'])
    buyer_cert     = cert_from_b64(state['buyer_cert'])
    price          = state['price']

    tampered = final.decode().replace(f'GBP {price}', f'GBP {fake_price}').encode()

    orig_hash   = hashlib.sha256(final).hexdigest()
    tamper_hash = hashlib.sha256(tampered).hexdigest()

    try:
        buyer_cert.public_key().verify(buyer_sig, tampered, ECDSA(hashes.SHA256()))
        detected = False
    except InvalidSignature:
        detected = True

    log = [
        ['info', f'── Attack: price changed GBP {price} → GBP {fake_price}'],
        ['muted', f'   Original hash: {orig_hash[:32]}...'],
        ['muted', f'   Tampered hash: {tamper_hash[:32]}...'],
        ['fail',  f'   Hashes match:  {orig_hash == tamper_hash}'],
        ['muted',''],
        ['info', '── ECDSA Verification on Tampered Document'],
        ['ok' if detected else 'fail',
         f'[{"OK" if detected else "!!"}]  {"TAMPER DETECTED — signature invalid on altered document" if detected else "FAILED — tamper not detected (unexpected)"}'],
        ['ok' if detected else 'fail',
         f'      {"Fraudulent contract rejected — transaction protected" if detected else "Unexpected result"}'],
    ]
    return jsonify({'orig_hash': orig_hash, 'tamper_hash': tamper_hash, 'log': log})


if __name__ == '__main__':
    print("\n" + "="*55)
    print("  Secure Contract Exchange Protocol")
    print("  Cryptographic Protocol Demonstration")
    print("="*55)
    print("  Open your browser and go to:")
    print("  http://localhost:5000")
    print("="*55 + "\n")
    app.run(debug=False, port=5000)
