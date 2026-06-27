# Command & Control Forum

A modern, lightweight, and highly secure web forum built with a visual design inspired by Command and Control console aesthetics. This forum utilizes client-side asymmetric cryptography in the browser to ensure that every thread, reply, and vote is digitally signed by its author, implementing a strict non-repudiation security model.

---

## Technical Architecture & Hardening

This platform is engineered to defend against common attack vectors and automated registration bots. The system is split into a Zero-Trust client application and a strictly validated REST and WebSocket backend.

### 1. Asymmetric Cryptography & Client-Side Key Isolation
Every write operation (thread creation, commenting, or voting) undergoes cryptographic signature verification:
*   **ECDSA Key Pairs:** Users generate an Elliptic Curve Digital Signature Algorithm (ECDSA) key pair using the NIST-approved P-256 curve directly in the browser via the Web Crypto API (`crypto.subtle`).
*   **Non-Extractable Keys in IndexedDB:** To prevent cross-site scripting (XSS) or browser extensions from stealing the private key, it is committed to a local browser database (`IndexedDB`) with the property `extractable: false`. The private key remains inside the browser's cryptographic engine and cannot be read or exported via JavaScript.
*   **Server Verification:** The backend does not trust any user-supplied metadata. It imports the user's public key (stored as SPKI) and verifies the ECDSA signature of the exact payload string before saving threads or comments.

### 2. Freshness Protocol & Replay Attack Mitigation
To prevent attackers from capturing network requests and replaying them to duplicate posts or votes (Replay Attacks):
*   **Cryptographic Nonces:** Every request requires a unique client-side generated UUIDv4 (`client_nonce`) and a microsecond-accurate UTC timestamp (`client_timestamp`).
*   **Stateful Checks:** The server retains a log of all processed nonces. It rejects any request that reuses a nonce or has a timestamp that deviates from the server's time window by more than 5 minutes.

### 3. Defensive Anti-Bot & Sybil Resistance
To prevent automated accounts, scrapers, and agentic AIs from registering, a multi-layered check is performed at the registration endpoint:
*   **Proof-of-Work (PoW) Challenge:** Before submitting a registration, the client must solve a CPU-bound hashing challenge. It must find a salt value that, when concatenated with the server-supplied challenge string, yields a SHA-256 hash starting with 5 leading hexadecimal zeroes. This increases the CPU cost of bulk registrations by a factor of 16.
*   **Vector CAPTCHA (SVG Path Distortion):** The CAPTCHA image is generated dynamically on the backend without raw text tags. Characters are drawn by mapping coordinates to SVG vector lines (`<path d="..." />`) distorted with random floating-point coordinate noise (+-0.4 pixels) per node. This prevents bots from parsing raw HTML XML text nodes or using basic lookup tables, forcing them to rasterize and run vision-based models.
*   **Honeypot Decoy:** An invisible input field (`name="email"`) is rendered off-screen. Automated scrapers and AI agents fill this field dynamically, which triggers immediate registration rejection at the server level.

### 4. Silent Moderation & Account Purging
Commanders have advanced, quiet moderation capabilities:
*   **Shadowbanning:** Users marked as shadowbanned can still browse, write posts, and see their own content. However, the server dynamically alters `GET /api/threads` and `GET /api/threads/:id/replies` queries to filter out their threads and replies for everyone else on the network.
*   **Atomic Purges:** Executing a user purge initiates an ACID transaction in SQLite, immediately terminating all WebSocket connections, deleting active sessions, and wiping out all threads, comments, and votes associated with the user across the database cascade.

### 5. Backend Rate-Limiting & Buffering
*   **Payload Size Limitation:** The WebSocket server restricts the handshake and message buffer (`maxHttpBufferSize`) to a maximum of 5KB, preventing memory exhaustion (DoS) from oversized payloads.
*   **Rate Limiters:** REST write operations are throttled using custom rate limiters that persist hits in a dedicated database table.

---

## Project Structure

*   `server.js`: Express web server, REST endpoints, WAL-mode SQLite database persistence, and Socket.io WebSocket engine.
*   `server/captcha.js`: Vector path calculation, SVG rendering, and Proof-of-Work verification module.
*   `public/app.js`: Frontend application state, Web Crypto P-256 engine, IndexedDB keystore, and History API SPA router.
*   `public/index.html`: Shell layout for the dark terminal aesthetic.
*   `public/index.css`: UI stylesheets.
*   `setup.js`: CLI tool for initializing administrative accounts (COMMANDER role).

---

## Installation & Setup

1.  **Install Dependencies:**
    ```bash
    npm install
    ```

2.  **Provision Administrative Account:**
    Because admin/commander accounts cannot be registered from the public web interface, you must configure the initial credentials locally:
    ```bash
    node setup.js --init-commander
    ```
    Follow the prompts to configure your username and access key.

3.  **Start Web Server:**
    ```bash
    npm start
    ```
    Alternatively, to start the application with automated Cloudflare tunnel integration, run:
    ```bash
    .\deploy.bat
    ```

4.  **Access:**
    Open `http://localhost:3000` (or the public tunnel address) in your browser.
