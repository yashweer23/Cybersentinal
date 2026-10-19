# Publish CyberSentinel to GitHub

The goal is a **GitHub repository containing the full project**, with the application running locally through Docker Compose. No Render account, paid cloud plan, deployment secret or GitHub Pages configuration is required. The existing optional `render.yaml` and cloud scripts are inactive unless you explicitly use them later.

## Choose the source folder

The `CyberSentinel-GitHub-Ready.zip` package contains the complete source under `cybersentinel/`, including backend, frontend, migrations, tests, documentation and existing synthetic-data screenshots. It is not an incremental phase patch.

- For a fresh copy, extract it into a new folder and open the extracted `cybersentinel` folder in VS Code.
- If you already have the latest working project, keep that folder and its database. Apply only the documentation/ignore changes you want; do not replace your local `.env`, remove volumes or overwrite newer work with this snapshot.
- The package has no `.git` history, real `.env`, installed dependencies, compiled frontend, generated events, logs or database backups. Generate an environment and demo data using the existing [setup](SETUP.md) and [demo](DEMO.md) guides.

## Create the GitHub repository

Open [GitHub's new repository page](https://github.com/new).

1. Name it `cybersentinel` (or another name you prefer).
2. Select your account as owner and choose visibility. Public is suitable when you want recruiters to browse the code; private is also supported.
3. Leave **Add a README**, **Add .gitignore** and **Choose a license** unset for this initial import, since the project already has its source files. No license is assigned by this package; make that choice separately if you want to grant reuse rights.
4. Create the repository, then copy its HTTPS URL from GitHub. It should have the form `https://github.com/<your-account>/<your-repository>.git`. Use your actual URL, not these placeholders.

This package has not created or pushed a repository on your account.

## First upload — Windows PowerShell

Install Git for Windows if `git --version` fails. Open the VS Code terminal **inside the project root**, where `README.md`, `docker-compose.yml`, `backend/` and `frontend/` are present.

If the project is already a Git repository, use the next section instead. For the newly extracted source folder:

```powershell
git --version
git init -b main
if ($LASTEXITCODE -ne 0) { throw 'Git initialization failed.' }

git add .
if ($LASTEXITCODE -ne 0) { throw 'Git staging failed.' }
git status --short
git diff --cached --stat
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Fix the reported staged-file issues before committing.' }
```

Review the file list: it should contain source, lockfiles, tests, documentation and `.env.example`, with no real `.env`, tokens, backups or generated event data. `.gitignore` excludes these normal local artifacts, but does not remove files that were already tracked in an older repository.

Then commit and publish:

```powershell
git commit -m "Add CyberSentinel SOC platform"
if ($LASTEXITCODE -ne 0) { throw 'Commit failed; read the Git message before continuing.' }

$repoUrl = Read-Host 'Paste the HTTPS URL of your empty GitHub repository'
git remote add origin "$repoUrl"
if ($LASTEXITCODE -ne 0) { throw 'Remote setup failed; inspect git remote -v.' }
git remote -v
git push -u origin main
if ($LASTEXITCODE -ne 0) { throw 'Push failed; read the Git message.' }
```

Complete GitHub's browser sign-in if Git Credential Manager prompts. Do not put a personal access token in the repository URL, source code or terminal command. No GitHub API key is part of CyberSentinel's `.env`.

If Git asks for author identity, set it for this repository and retry the commit. Enter the name and commit email you actually want GitHub to show; a GitHub-provided no-reply email is available in your account's email settings.

```powershell
$commitName = Read-Host 'Name for your Git commits'
$commitEmail = Read-Host 'Verified GitHub email or your GitHub no-reply email'
git config user.name "$commitName"
git config user.email "$commitEmail"
```

## Existing Git repository

Preserve your existing history and branch. Start by checking the destination:

```powershell
git status --short
git branch --show-current
git remote -v
```

If `origin` already points to the correct GitHub repository, leave it unchanged. If no remote exists, add the actual empty repository URL with `git remote add origin` as above. Do not overwrite a remote or force-push to solve a conflict.

After reviewing local changes:

```powershell
git add .
if ($LASTEXITCODE -ne 0) { throw 'Staging failed.' }
git diff --cached --stat
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Fix staged-file issues before continuing.' }
git commit -m "Prepare CyberSentinel for GitHub publication"
# If Git reports nothing to commit, inspect status and skip the commit.
git push -u origin HEAD
```

`HEAD` publishes the current named branch; do not rename an established branch solely to follow the first-upload example. If the remote already contains commits, fetch and inspect its history before reconciling changes. Do not use `--force`.

## Confirm the published repository

Open the actual GitHub repository URL and verify:

- The root README renders and its existing screenshot links load.
- `backend`, `frontend`, `scripts`, `docs` and `docker-compose.yml` appear at the repository root, without an extra accidental nesting level.
- Dependency lockfiles, Alembic migrations and tests are included.
- No real `.env`, backup archives, local accounts/passwords, provider keys, dependency directories or generated runtime data appear.
- The setup instructions describe local execution and do not claim that a public application is deployed.

Upload the extracted project using Git; do not upload the ZIP itself as the repository's only file.

## Repository presentation

Suggested About description:

> Defensive SOC-style platform using FastAPI, React and PostgreSQL, with behavioral detections, explainable risk scoring, incident investigation and evidence-grounded AI assistance.

Suggested topics: `cybersecurity`, `soc`, `fastapi`, `react`, `postgresql`, `docker`, `threat-intelligence`, `security-analytics`, `python`.

Leave the repository's Website field empty unless you have an actual live website. Pin the repository to your profile after publication. Use the [existing two-bullet resume description](INTERVIEW.md#one-page-resume-compact-version), adding the real repository link. Describe the application as built/containerized/tested, rather than cloud-deployed.

## Run the application locally

Use the full [README quick start](../README.md#quick-start) on a fresh checkout. On your already initialized installation:

```powershell
docker compose up --build -d --wait --wait-timeout 180
if ($LASTEXITCODE -ne 0) { throw 'Container startup failed.' }
Invoke-RestMethod http://localhost:5173/api/system/ready
Start-Process http://localhost:5173
```

Publishing source does not require a database reset, new credentials or new demo users. GitHub stores code, while your local Docker volumes retain your local database. GitHub Pages is a static hosting service and cannot run this application's Python backend or database.

## Preparation record

This repository-publication update changes documentation, ignore patterns and whitespace flagged by Git during the first import. It does not change application behavior, migration logic, dependencies or existing test results. The latest recorded full checks are the 2026-10-18 run: 837 backend passes and one native-concurrency skip, 86 frontend passes, a successful production build and a 10,000-event local pipeline. See [PHASE18_VALIDATION.md](PHASE18_VALIDATION.md) for the environment and limitations; these tests were not rerun merely for this documentation update.

The publication package is checked for ignore behavior, required files, documentation links, secret-like credential patterns and archive integrity. These checks are preparation for publication, not a claim that code has already been pushed to GitHub or that an exhaustive security audit occurred.

Official guidance: [adding local code to GitHub](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github), [GitHub Pages capabilities](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).
