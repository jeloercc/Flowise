# Zero-Context Guard — Live Demo Deployment

This guide deploys the `zero-context-guard` branch as a public live demo on either
**Render** or **Railway** using the existing root [`Dockerfile`](../Dockerfile).
No modifications to `packages/` are required.

> **Warning — fake keys only.** The demo instance must never hold real API keys.
> Use placeholder values for every LLM provider credential. See
> [`docs/DEPLOY_CHECKLIST.md`](../docs/DEPLOY_CHECKLIST.md) before you go live.

---

## Environment variables

Set every variable below in your platform's environment / secrets panel.
Copy [`deploy/.env.example`](.env.example) as a starting point and replace the
`CHANGE_ME_*` placeholders with real random values for the auth secrets.

| Variable                    | Required    | Description                                                                                       |
| --------------------------- | ----------- | ------------------------------------------------------------------------------------------------- |
| `PORT`                      | yes         | Port the server listens on. Render/Railway inject this automatically; set `3000` if not.          |
| `FLOWISE_USERNAME`          | yes         | Admin username for the UI login.                                                                  |
| `FLOWISE_PASSWORD`          | yes         | Admin password — change after judging.                                                            |
| `DATABASE_PATH`             | yes         | Absolute path inside the container to the SQLite DB file. Use `/data/.flowise` (see volume note). |
| `SECRETKEY_PATH`            | yes         | Path for the Flowise encryption key. Use `/data/.flowise` (same persistent dir).                  |
| `HTTP_SECURITY_CHECK`       | yes         | **Must be `true`** — keeps the SSRF deny list active.                                             |
| `DISABLE_FLOWISE_TELEMETRY` | recommended | Set `true` to suppress upstream telemetry.                                                        |
| `JWT_AUTH_TOKEN_SECRET`     | yes         | Random 32-char string — used to sign login tokens.                                                |
| `JWT_REFRESH_TOKEN_SECRET`  | yes         | Random 32-char string — used to sign refresh tokens.                                              |
| `EXPRESS_SESSION_SECRET`    | yes         | Random 32-char string — used for express sessions.                                                |

Generate secrets with:

```bash
openssl rand -hex 32
```

---

## Option A — Render (Docker Web Service)

### Prerequisites

-   A Render account (free tier is enough for judging)
-   The `zero-context-guard` branch pushed to GitHub

### Steps

1. **Create a new Web Service** at https://dashboard.render.com/  
   → _New_ → _Web Service_ → connect your GitHub repo.

2. **Configure the service:**

    - Environment: **Docker**
    - Branch: `zero-context-guard`
    - Dockerfile path: `./Dockerfile` (root of repo)
    - Instance type: **Starter** (512 MB RAM) or higher
        > The build step compiles the full monorepo; it needs ≥ 1 GB RAM.
        > Use **Standard** (2 GB) if the build OOMs on Starter.

3. **Add a Persistent Disk:**

    - Mount path: `/data`
    - Size: 1 GB is plenty for a demo

4. **Set environment variables** (Render → Environment tab):

    ```
    PORT=3000
    FLOWISE_USERNAME=demo
    FLOWISE_PASSWORD=<your-demo-password>
    DATABASE_PATH=/data/.flowise
    SECRETKEY_PATH=/data/.flowise
    HTTP_SECURITY_CHECK=true
    DISABLE_FLOWISE_TELEMETRY=true
    JWT_AUTH_TOKEN_SECRET=<openssl rand -hex 32>
    JWT_REFRESH_TOKEN_SECRET=<openssl rand -hex 32>
    EXPRESS_SESSION_SECRET=<openssl rand -hex 32>
    ```

5. **Deploy.** Render will build the Dockerfile from source.
   First build takes 10–20 minutes (full pnpm install + build).

6. Note your service URL (e.g. `https://zero-context-guard.onrender.com`).

### Free-tier caveat

Render free instances spin down after 15 minutes of inactivity and take ~30 s
to cold-start. For a hackathon demo this is acceptable; warn visitors.

---

## Option B — Railway (Docker service)

### Prerequisites

-   A Railway account — https://railway.com
-   The branch pushed to GitHub

### Steps

1. **New Project** → _Deploy from GitHub repo_ → select the repo and branch
   `zero-context-guard`.

2. Railway auto-detects the root `Dockerfile`. Confirm it is selected.

3. **Add a Volume:**

    - Mount path: `/data`
    - This persists the SQLite DB and encryption key across redeploys.

4. **Set environment variables** (Railway → Variables tab):

    ```
    PORT=3000
    FLOWISE_USERNAME=demo
    FLOWISE_PASSWORD=<your-demo-password>
    DATABASE_PATH=/data/.flowise
    SECRETKEY_PATH=/data/.flowise
    HTTP_SECURITY_CHECK=true
    DISABLE_FLOWISE_TELEMETRY=true
    JWT_AUTH_TOKEN_SECRET=<openssl rand -hex 32>
    JWT_REFRESH_TOKEN_SECRET=<openssl rand -hex 32>
    EXPRESS_SESSION_SECRET=<openssl rand -hex 32>
    ```

5. Railway assigns a public URL automatically under `*.up.railway.app`.

6. First deploy builds from source (10–15 minutes).

---

## Importing the demo chatflow

A pre-built chatflow is provided at
[`demo/chatflow-zero-context-guard.json`](../demo/chatflow-zero-context-guard.json).
It contains two Custom Tools that illustrate the guard contrast:

-   **SecureTool (with bindings)** — has `secretBindings` for a credential named
    `demo-api` pointing to a harmless public echo endpoint
    (`httpbin.org`). `$vars` is absent from the sandbox; the tool calls
    `$secureRequest('demo-api', ...)`. The credential value is a fake key.
-   **UnsecuredTool (no bindings)** — has no `secretBindings`. The tool code
    attempts to read and return `JSON.stringify($vars)` to demonstrate what an
    unguarded tool would expose.

### Import steps

1. Log in to the demo instance.
2. Navigate to **Chatflows** → click the **Import** button (top-right).
3. Select `demo/chatflow-zero-context-guard.json`.
4. Open the imported chatflow in the editor.
5. Click the **SecureTool** node → **Credentials** tab → add a credential named
   `demo-api` with the value `sk-FAKE-DEMO-0000000000`. Set `allowedHosts` to
   `httpbin.org`.
6. Save and use the built-in chat widget to run both tools.

> The credential value is intentionally fake (`sk-FAKE-DEMO-0000000000`).
> The live demo uses no real LLM or API keys.

---

## What cannot be verified locally

The following were NOT verified by running a live deployment from this machine:

1. **Build time / RAM headroom** — the Dockerfile runs `pnpm install && pnpm build:docker`
   inside the container. On Render Starter (512 MB) this may OOM; Standard (2 GB)
   is recommended but untested from here.
2. **Persistent volume mount** — the container runs as the `node` user (UID 1000).
   Render and Railway provision volumes owned by root; the `chown -R node:node .`
   step in the Dockerfile covers the app dir but not the mounted `/data` path.
   If the DB fails to initialise, run `chown -R 1000:1000 /data` in a one-off
   shell command on the platform.
3. **Cold-start latency** — Render free tier cold-starts are ~30 s; not measured.
4. **JWT token behaviour** — `EXPIRE_AUTH_TOKENS_ON_RESTART=false` (default) is
   assumed; flip to `true` if you want tokens to invalidate on each redeploy.
