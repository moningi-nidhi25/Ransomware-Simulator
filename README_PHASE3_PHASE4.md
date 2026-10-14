# RansomShield — Phase 3 & Phase 4 (repository-integrated)

This package is based on the uploaded `Ransomware-Simulator` repository. It keeps the existing Phase 1/2 detector, monitor, event processor tests, sample files, and React/Vite structure while adding Phase 3 database/API features and a Phase 4 dashboard.

## Phase 3 additions
- SQLite migration that adds alert metadata without dropping the existing `alerts` rows.
- Persistent file event records and configurable detector thresholds.
- Alert filtering, detail endpoint, and status updates.
- Statistics endpoint, settings endpoints, and CSV report export.
- Safe synthetic `normal` and `suspicious` simulations.

## Phase 4 additions
- Dashboard KPI cards, recent file-event chart, latest detection panel.
- Alert table with severity/source/status filters and status updates.
- Settings form and CSV export link.
- No new frontend library required.

## Requirements
The repository currently declares Python `>=3.14` in `backend/pyproject.toml`. Use the Python version your team already uses with this repository. Node.js LTS is required for the frontend.

## Start backend (PowerShell terminal 1)

```powershell
cd backend
uv sync
uv run uvicorn main:app --reload
```

Open API documentation at http://127.0.0.1:8000/docs.

If you do not have `uv`, install it using the official instructions at https://docs.astral.sh/uv/getting-started/installation/ and reopen your terminal.

## Start frontend (PowerShell terminal 2)

```powershell
cd frontend
npm install
npm run dev
```

Open the URL printed by Vite, normally http://localhost:5173.

## Test the backend

From the `backend` folder:

```powershell
uv run pytest
```

Try these routes in Swagger (`/docs`):
- `GET /api/health`
- `GET /api/alerts`
- `POST /api/simulate/normal`
- `POST /api/simulate/suspicious`
- `GET /api/stats`
- `GET /api/settings`
- `PUT /api/settings`
- `GET /api/events`
- `GET /api/reports/export`

## Optional file monitor

Monitoring is **off by default**. It only watches `backend/test_data`, which contains the sample files from the repository. To enable it in PowerShell for the current terminal:

```powershell
$env:ENABLE_FILE_MONITOR = "1"
uv run uvicorn main:app --reload
```

To disable it, close the terminal or run:

```powershell
Remove-Item Env:ENABLE_FILE_MONITOR
```

Do not point the monitor at personal folders or important files. The synthetic simulation endpoints do not read, encrypt, modify, or delete files.

## Integration note

Use a branch before merging these changes into the shared GitHub repository. The ZIP contains the full repository snapshot with the Phase 3/4 changes integrated locally; it does not push changes to GitHub automatically.
