# Forged Origin Hijack Detection API

This API provides access to **DFOH** inference data.  
It enables querying suspicious/legitimate BGP link inferences, retrieving detailed per-observation data, and submitting operator feedback.

---

## 🚀 API Endpoints

### `GET /new_links`

Retrieve a list of **new links** (potential hijack cases) that match specific filters.

#### ✅ Successful Response

Returns a list of link summaries, each containing:

* `id`: Unique link identifier  
* `date`: Observation timestamp (`YYYY-MM-DD HH:MM:SS`)  
* `as1`: First ASN of the link  
* `as2`: Second ASN of the link  
* `presumed_attacker`: List of suspected attacker ASNs  
* `presumed_victims`: List of suspected victim ASNs  
* `inference_result`: `"legitimate"`, `"suspicious"`, or `"unknown"`  
* `confidence_level`: Confidence score (0–5)  
* `nb_aspaths_observed`: Number of distinct AS paths observed  
* `is_reccurent`: `true`/`false` (whether the new edge is recurrent)  
* `operator_feedback` (optional): Human feedback text (if provided and authorized)  
* `operator_comment` (optional): Extended operator comment  

---

#### 🔍 Query Parameters

| Parameter               | Type       | Description                                                                                           |
| ----------------------- | ---------- | ----------------------------------------------------------------------------------------------------- |
| `asn`                   | string     | Comma-separated list of ASNs. Matches either end of the link.                                         |
| `attackers`             | string     | Comma-separated ASNs suspected as attackers.                                                          |
| `victims`               | string     | Comma-separated ASNs suspected as victims.                                                            |
| `inference_result`      | string     | `"legitimate"` or `"suspicious"`. Filters by inferred legitimacy.                                      |
| `min_confidence_level`  | int        | Minimum confidence score (0–5).                                                                       |
| `nb_max_aspaths`        | int        | Maximum number of observed AS paths.                                                                  |
| `nb_min_aspaths`        | int        | Minimum number of observed AS paths.                                                                  |
| `start_time`            | string     | Minimum observation time. Format: `YYYY-MM-DDTHH:MM:SS`. Defaults to today if not set.                 |
| `stop_time`             | string     | Maximum observation time. Format: `YYYY-MM-DDTHH:MM:SS`. Defaults to same as `start_time` if not set. |
| `new_link_ids`          | string     | Comma-separated list of specific link IDs to query.                                                   |

---

**Example request:**

```bash
curl "http://127.0.0.1:5555/new_links?asn=3356,174&inference_result=suspicious&min_confidence_level=3&start_time=2023-01-01T00:00:00"
```

---

### `GET /inference_details`

Retrieve detailed per-observation information for given link IDs.  
Each inference ID corresponds to a set of observed paths and prefixes.

#### ✅ Successful Response

Returns a dictionary keyed by link ID. Each entry is a list of tuples:

* `observed_at`: Timestamp (`YYYY-MM-DD HH:MM:SS`)  
* `asn1`, `asn2`: The AS link involved  
* `peer_asn`: ASN of vantage point peer  
* `peer_ip`: IP address of vantage point peer  
* `as_path`: Observed AS path  
* `prefix`: Observed prefix  
* `inference_result`: `"legitimate"`, `"suspicious"`, or `"unknown"`  
* `confidence_level`: Confidence score (0–5)  
* `asp_tags`: (reserved, list of AS-path tags – currently empty)  
* `pfx_tags`: List of prefix tags (`"RPKI valid"`, `"RPKI invalid"`, `"Origin invalid"`)  

---

#### 🔍 Query Parameters

| Parameter       | Type   | Description                                                                                 |
| --------------- | ------ | ------------------------------------------------------------------------------------------- |
| `new_link_ids`  | string | **Required.** Comma-separated list of link IDs. Maximum 100 IDs.                            |

---

**Example request:**

```bash
curl "http://127.0.0.1:5555/inference_details?new_link_ids=123,456,789"
```

---

### `GET /operator_feedback`

Submit operator feedback about a specific new link.

#### ✅ Successful Response

```json
{
  "code": 200,
  "detail": "Operator feedback correctly added."
}
```

---

#### 🔍 Query Parameters

| Parameter            | Type   | Description                                                                                  |
| -------------------- | ------ | -------------------------------------------------------------------------------------------- |
| `new_link_id`        | int    | Identifier of the link to annotate.                                                          |
| `decision`           | string | Operator classification: `"legitimate"`, `"suspicious"`, or `"unknown"`.                     |
| `feedback`           | string | Optional extended operator comment.                                                          |
| `authorize_others`   | bool   | If `true`, feedback is visible to other users.                                               |
| `grant_feedback_use` | bool   | If `true`, feedback may be used for measurement/analysis.                                     |
| `api_key`            | string | **Required.** API key (must match environment variable `SECURED_WRITE_API_KEY`).             |

---

**Example request:**

```bash
curl "http://127.0.0.1:5555/operator_feedback?new_link_id=123&decision=suspicious&feedback=Confirmed+by+manual+check&authorize_others=true&grant_feedback_use=true&api_key=MY_SECRET_KEY"
```

---

## 📦 Notes

* List parameters (`asn`, `attackers`, etc.) must contain **only integers** and are comma-separated.  
* Time parameters must be in ISO format: `YYYY-MM-DDTHH:MM:SS`.  
* `inference_result` is **human-readable** (`legitimate`/`suspicious`) instead of old `classification=leg/sus`.  
* Operator feedback endpoint is **write-protected** with an API key.  
* Default time range is **today** if `start_time`/`stop_time` are not specified.  
* `confidence_level` is scaled **0–5** (not 0–100 as in the old API).  


---

## 🛠 Running the API

The API is implemented with **FastAPI** and **Uvicorn**, and requires access to a PostgreSQL database.

### 1. Environment Variables

Before running, make sure to set the following environment variables:

```bash
export DB_NAME="your_database_name"
export DB_USER="your_database_user"
export DB_PASSWORD="your_database_password"
export DB_HOST="your_database_host"
export DB_PORT="5432"

# Required for /operator_feedback endpoint
export SECURED_WRITE_API_KEY="your_secret_api_key"
```

### 2. Install dependencies

We recommend using a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Typical dependencies include:

- fastapi
- uvicorn
- psycopg2

### 3. Run the API

You can start the API directly using Python:

```bash
python -m api.py
```

Or run via Uvicorn manually:

```bash
uvicorn api:DFOHExternalAPI().app --host 0.0.0.0 --port 5555
```

By default, the API listens on **http://127.0.0.1:5555**.

### 4. Test the API

Once running, you can test endpoints with curl, for example:

```bash
curl "http://127.0.0.1:5555/new_links?asn=3356&inference_result=suspicious"
```
