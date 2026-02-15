<p align="center">
  <img src="./img.png" alt="Project Banner" width="100%">
</p>

# [Sieve] 🎯

## Basic Details

### Team Name: [GAYATHRI M]

### Team Members
- Member 1: [GAYATHRI M] - [SCMS SCHOOL OF ENGINEERING AND TECHNOLOGY]


### Hosted Project Link
[https://sieve-lemon.vercel.app/]

### Project Description
[Sieve is an intelligent automated middleware for GitHub repositories that filters pull requests before they reach the maintainer. By leveraging regex-based parsing and Large Language Models (LLMs), it acts as a quality control layer, analyzing the intent, effort, and relevance of every submission to ensure only high-value code enters the review queue.]

### The Problem statement
[Open-source maintainers are overwhelmed by a flood of low-quality contributions, including "typo-hunting" spam, AI-generated code dumps, and trivial whitespace changes. Current CI tools only verify syntax and build status, failing to detect the "spammy" intent or low-effort nature of these submissions, which drains valuable maintainer time and energy.]

### The Solution
[Sieve deploys a multi-stage analysis pipeline that calculates an "Effort-to-Noise" ratio and verifies the semantic alignment between code changes and the linked issue. It autonomously closes irrelevant or low-effort PRs with a contextual explanation, while valid, high-intent contributions are labeled and promoted to the maintainer's dashboard for final approval.]

---

## Technical Details

### Technologies / Components Used

- **Languages:** Python 3.12, JavaScript (React)
- **Backend framework:** FastAPI (served with `uvicorn`)
- **Worker / background processing:** Celery
- **Broker / cache:** Redis
- **Database:** PostgreSQL (Supabase-compatible) with `asyncpg` / `psycopg2`, ORM via SQLAlchemy and migrations via Alembic
- **HTTP clients & misc:** `httpx`, `requests`, `tenacity`
- **Validation & config:** Pydantic (v2) and `python-dotenv`
- **GitHub integration:** `PyGithub`, GitHub OAuth support
- **Other notable Python deps:** `cryptography`, `groq`, `pyyaml`
- **Frontend:** React 19 + Vite, `@vitejs/plugin-react`, ESLint
- **Dev tooling:** Node/npm, Vite (frontend dev server), repo Python virtualenv for backend

### Run (local development)

- Backend (using the repository virtualenv):

  1. Activate the venv (if present):

     ```bash
     source .venv/bin/activate
     ```

  2. Start the app (entrypoint runs uvicorn):

     ```bash
     python main.py
     ```

  - Defaults: `HOST=127.0.0.1`, `PORT=8000` → http://127.0.0.1:8000
  - Disable automatic Celery worker spawn: `START_WORKER=false`
  - Enable auto-reload for dev: `RELOAD=true`

- Frontend (React + Vite):

  ```bash
  cd frontend
  npm install
  npm run dev
  ```

  - Vite dev server default: `http://localhost:5173` (frontend reads `VITE_API_BASE` / `VITE_API_TARGET` in `frontend/.env` or `frontend/.env.example`)

s
---

## Features

List the key features of your project:
- PR Pre-screening: Auto-analyzes incoming PRs for relevance and quality.
- Effort-to-Noise Scoring: Produces a single score combining heuristics and LLM signals.
- Auto Actions: Auto-labels, comments, or closes low-effort PRs with explanations.
- Async Pipeline & Integrations: Celery workers + GitHub webhooks, Redis, Postgres for scalable processing.
---

## Implementation

### For Software:

#### Installation

1. Create and activate a Python virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

2. Install backend dependencies (uses `pyproject.toml`):

```bash
# Editable install for development
pip install -e .
# Alternatively, if you have a requirements file:
# pip install -r requirements.txt
```

3. Install frontend dependencies (optional, for UI):

```bash
cd frontend
npm install
cd ..
```

4. Configure environment variables:

```bash
# Copy example env files and edit values
cp frontend/.env.example frontend/.env || true
# Create a backend .env at repo root and populate the variables below
```

Important backend env vars (set in `.env`):

- `SUPABASE_URL` and `SUPABASE_KEY` (or a Postgres DSN in `SUPABASE_URL`)
- `GROQ_API_KEY` (LLM provider key)
- `REDIS_URL` (e.g. redis://localhost:6379)
- `GITHUB_WEBHOOK_SECRET`, `GITHUB_TOKEN`, `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`

If you need ephemeral services for development, run simple Docker containers:

```bash
# Postgres
docker run -d --name sieve-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:15
# Redis
docker run -d --name sieve-redis -p 6379:6379 redis:7
```

#### Run

1. Apply database migrations (if using Alembic / SQLAlchemy migrations):

```bash
alembic upgrade head
```

2. Start background worker(s) (Celery example):

```bash
# from repo root, with venv active
celery -A app.worker worker --loglevel=info
```

3. Start the backend API (FastAPI / Uvicorn):

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

4. Start the frontend dev server (optional):

```bash
cd frontend
npm run dev
```

Defaults:

- Backend: http://127.0.0.1:8000
- Frontend: http://localhost:5173

Use `curl` or the frontend UI to exercise the system during development.

---

## Project Documentation

### For Software:

#### Screenshots (Add at least 3)

![img1](screenshots/img1.png)
*Caption: Main dashboard showing PR scan results and overall Effort-to-Noise scoring.*

![img2](screenshots/img2.png)
*Caption: Pull request detail view with inline analysis and suggested actions.*

![img3](screenshots/img3.png)
*Caption: Maintainer review dashboard highlighting auto-labeled and closed PRs.*

#### Diagrams

**System Architecture:**

![Architecture Diagram](docs/architecture.png)
*Explain your system architecture - components, data flow, tech stack interaction*

**Application Workflow:**

![Workflow](docs/workflow.png)
*Add caption explaining your workflow*

---

## Additional Documentation

### For Web Projects with Backend:

#### API Documentation

**Base URL:** `https://api.yourproject.com`

##### Endpoints

**GET /api/endpoint**
- **Description:** [What it does]
- **Parameters:**
  - `param1` (string): [Description]
  - `param2` (integer): [Description]
- **Response:**
```json
{
  "status": "success",
  "data": {}
}
```

**POST /api/endpoint**
- **Description:** [What it does]
- **Request Body:**
```json
{
  "field1": "value1",
  "field2": "value2"
}
```
- **Response:**
```json
{
  "status": "success",
  "message": "Operation completed"
}
```

[Add more endpoints as needed...]

---

---

### For Scripts/CLI Tools:

#### Command Reference

**Basic Usage:**
```bash
python script.py [options] [arguments]
```

**Available Commands:**
- `command1 [args]` - Description of what command1 does
- `command2 [args]` - Description of what command2 does
- `command3 [args]` - Description of what command3 does

**Options:**
- `-h, --help` - Show help message and exit
- `-v, --verbose` - Enable verbose output
- `-o, --output FILE` - Specify output file path
- `-c, --config FILE` - Specify configuration file
- `--version` - Show version information

**Examples:**

```bash
# Example 1: Basic usage
python script.py input.txt

# Example 2: With verbose output
python script.py -v input.txt

# Example 3: Specify output file
python script.py -o output.txt input.txt

# Example 4: Using configuration
python script.py -c config.json --verbose input.txt
```

#### Demo Output

**Example 1: Basic Processing**

**Input:**
```
This is a sample input file
with multiple lines of text
for demonstration purposes
```

**Command:**
```bash
python script.py sample.txt
```

**Output:**
```
Processing: sample.txt
Lines processed: 3
Characters counted: 86
Status: Success
Output saved to: output.txt
```

**Example 2: Advanced Usage**

**Input:**
```json
{
  "name": "test",
  "value": 123
}
```

**Command:**
```bash
python script.py -v --format json data.json
```

**Output:**
```
[VERBOSE] Loading configuration...
[VERBOSE] Parsing JSON input...
[VERBOSE] Processing data...
{
  "status": "success",
  "processed": true,
  "result": {
    "name": "test",
    "value": 123,
    "timestamp": "2024-02-07T10:30:00"
  }
}
[VERBOSE] Operation completed in 0.23s
```

---

## Project Demo

### Video
[Add your demo video link here - YouTube, Google Drive, etc.]

*Explain what the video demonstrates - key features, user flow, technical highlights*

### Additional Demos
[Add any extra demo materials/links - Live site, APK download, online demo, etc.]

---

## AI Tools Used (Optional - For Transparency Bonus)

If you used AI tools during development, document them here for transparency:

**Tool Used:** [e.g., GitHub Copilot, v0.dev, Cursor, ChatGPT, Claude]

**Purpose:** [What you used it for]
- Example: "Generated boilerplate React components"
- Example: "Debugging assistance for async functions"
- Example: "Code review and optimization suggestions"

**Key Prompts Used:**
- "Create a REST API endpoint for user authentication"
- "Debug this async function that's causing race conditions"
- "Optimize this database query for better performance"

**Percentage of AI-generated code:** [Approximately X%]

**Human Contributions:**
- Architecture design and planning
- Custom business logic implementation
- Integration and testing
- UI/UX design decisions

*Note: Proper documentation of AI usage demonstrates transparency and earns bonus points in evaluation!*

---

## Team Contributions

- [Name 1]: [Specific contributions - e.g., Frontend development, API integration, etc.]
- [Name 2]: [Specific contributions - e.g., Backend development, Database design, etc.]
- [Name 3]: [Specific contributions - e.g., UI/UX design, Testing, Documentation, etc.]

---

## License

This project is licensed under the [LICENSE_NAME] License - see the [LICENSE](LICENSE) file for details.

**Common License Options:**
- MIT License (Permissive, widely used)
- Apache 2.0 (Permissive with patent grant)
- GPL v3 (Copyleft, requires derivative works to be open source)

---

Made with ❤️ at TinkerHub
