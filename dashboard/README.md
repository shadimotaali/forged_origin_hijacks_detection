# 🛰️ DFOH Dashboard

The **DFOH Dashboard** is a web application for visualizing and analyzing BGP (Border Gateway Protocol) anomalies. It provides authenticated operator access, filters for custom queries, and interactive feedback features.  

The dashboard is available publicly at **[https://dfoh.uclouvain.be](https://dfoh.uclouvain.be)**, but you can also run it locally for development, testing, or private deployments.  

---

## 🚀 Features
- View **new BGP links** detected by the DFOH API.  
- Filter cases by ASN, attacker, victim, inference result, time window, recurrence, and more.  
- Submit **operator feedback** with options to share with others or anonymously.  
- Authentication via **PeeringDB OAuth2**.  
- Supports **pagination** and responsive tables.  
- Easily deployable using [Reflex](https://reflex.dev).  

---

## 🛠️ Prerequisites
- **Python 3.10+**  
- [Reflex](https://reflex.dev) (`reflex==0.8.12`)  
- [virtualenv](https://virtualenv.pypa.io/) or another Python environment manager (recommended)  
- A **PeeringDB account** (for OAuth authentication)  
- An API key for writing operator feedback (from your DFOH API deployment or the default `dfoh-api.bgproutes.io`)  

---

## 📦 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/bgproutes-io/forged_origin_hijacks_detection.git
cd forged_origin_hijacks_detection/dashboard

# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

The minimal `requirements.txt` includes:
```
jwt
reflex==0.8.12
```

---

## 🔑 Environment Configuration

The dashboard requires several environment variables. You can store them in a `.env` file at the project root.  

| Variable | Description | Example |
|----------|-------------|---------|
| `OAUTH2_PEERINGDB_CLIENT_ID` | OAuth client ID for PeeringDB | `your-client-id` |
| `OAUTH2_PEERINGDB_CLIENT_SECRET` | OAuth client secret for PeeringDB | `your-client-secret` |
| `SESSION_AUTHENTIFICATION_SECRET_KEY` | Secret key for local sessions (random string) | `super-secret-key` |
| `COOKIE_MAX_AGE` | Session cookie lifetime (in seconds) | `3600` |
| `WEBSITE_URL` | Redirect URL after OAuth authentication | `http://localhost:3000` (for local dev) |
| `SECURED_WRITE_API_KEY` | API key for submitting operator feedback | `my-secure-api-key` |
| `API_URL` | Base URL of the DFOH API | `https://dfoh-api.bgproutes.io` |

👉 If you deploy your own API, make sure `SECURED_WRITE_API_KEY` matches the secured key configured in your API backend.

Example `.env` file:
```env
OAUTH2_PEERINGDB_CLIENT_ID=xxxx
OAUTH2_PEERINGDB_CLIENT_SECRET=xxxx
SESSION_AUTHENTIFICATION_SECRET_KEY=mysecret
COOKIE_MAX_AGE=3600
WEBSITE_URL=http://localhost:3000
SECURED_WRITE_API_KEY=xxxx
API_URL=https://dfoh-api.bgproutes.io
```

---

## 🔐 Setting up PeeringDB OAuth Credentials

To authenticate operators, the dashboard uses **PeeringDB OAuth2**. You will need to configure a PeeringDB application to obtain your client ID and client secret.

1. Log in to your PeeringDB account: [https://peeringdb.com](https://peeringdb.com)  
2. Navigate to **Profile → Applications → Register New Application**.  
3. Fill in the required fields:  
   - **Name**: DFOH Dashboard (or any identifier you prefer)  
   - **Redirect URI**: set this to the value of `WEBSITE_URL` (e.g., `http://localhost:3000` for local development, or your production domain).  
   - **Description**: optional  
4. Once registered, PeeringDB will generate:  
   - **Client ID** → set as `OAUTH2_PEERINGDB_CLIENT_ID`  
   - **Client Secret** → set as `OAUTH2_PEERINGDB_CLIENT_SECRET`  

Make sure these values are copied into your `.env` file.  

---

## ▶️ Running Locally

Once your environment is set up:

```bash
reflex run
```

By default:
- Frontend runs at `http://localhost:3000`
- Backend runs at `http://localhost:8000`

### Customizing ports

You can change ports in `rxconfig.py`. See [Reflex configuration docs](https://reflex.dev/docs/advanced-onboarding/configuration/) for details.

---

## 🌐 Deployment

For production deployment:

1. Make sure environment variables are set on your server or container runtime (e.g., Docker, systemd, Kubernetes).  
2. Configure `rxconfig.py` for production (e.g., custom ports, SSL, allowed hosts). Example:

   ```python
   import reflex as rx

   config = rx.Config(
       app_name="dfoh",
       frontend_port=8080,
       backend_port=8081,
       log_level="info",
   )
   ```

3. Run with:
   ```bash
   reflex run --env prod
   ```

### Deployment options
- **Bare metal / VM**: run with systemd or supervisord.  
- **Docker**: build a container image with `reflex export --backend-only` or `--frontend-only`.  
- **Kubernetes**: deploy backend and frontend separately with your ingress controller.  
- **Cloud hosting**: see [Reflex deployment docs](https://reflex.dev/docs/advanced-onboarding/configuration/) for options.  

---

## 🧑‍💻 Development Notes
- Logs are written both to console and to `logs.log` (see `oauth.py`).  
- Authentication uses **JWT stored in secure cookies**.  
- The **operator feedback modal** supports:
  - Marking a case as `legitimate`, `suspicious`, or `unknown`.  
  - Free-text feedback.  
  - Sharing options (`authorize_others`, `grant_feedback_use`).  

---

## 🐞 Troubleshooting
- **OAuth login fails** → Double-check your `WEBSITE_URL` matches the redirect URI configured in your PeeringDB application.  
- **Feedback API errors** → Ensure `SECURED_WRITE_API_KEY` matches the API’s secured key.  
- **CORS issues** → Verify the API server allows requests from your dashboard frontend domain.  
- **Cookie not persisting** → If testing locally, ensure you access via `http://localhost` (not `127.0.0.1`) and check `secure=True` settings in cookies.  

If you encounter any issues or bugs with the code, please contact **[contact@bgproutes.io](mailto:contact@bgproutes.io)** for help.

---

## 📚 References
- Reflex Documentation: [https://reflex.dev](https://reflex.dev)  
- Reflex Configuration & Deployment: [https://reflex.dev/docs/advanced-onboarding/configuration/](https://reflex.dev/docs/advanced-onboarding/configuration/)  
- PeeringDB OAuth docs: [https://docs.peeringdb.com/oauth/](https://docs.peeringdb.com/oauth/)  

---

✨ With this setup, you should be able to run the DFOH dashboard locally, configure OAuth2 with PeeringDB, and deploy it in production.