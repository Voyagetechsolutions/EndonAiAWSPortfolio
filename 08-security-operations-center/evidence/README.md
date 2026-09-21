# Evidence

| Evidence | Source | Status |
|---|---|---|
| [`soc-board.txt`](soc-board.txt) | Offline SOC board from the platform snapshot (score, severity, health, incidents) | Captured |
| [`dashboard.html`](dashboard.html) | Static render of the server-rendered console (same numbers as the board) | Captured |
| `dashboard-console.png` | The web console in a browser | To capture |
| `incident-detail.png` | An incident page with its full action list and timeline | To capture |
| `cognito-signin.png` | The Cognito hosted sign-in gating the console | To capture |
| `api-summary.png` | `GET /api/summary` returning the score JSON behind auth | To capture |

## Capturing live evidence

1. Run `python 08-security-operations-center/attack-simulation/soc_walkthrough.py`; it prints
   the board and writes `soc-board.txt` and `dashboard.html`. Screenshot both.
2. Deploy the platform (`cdk deploy EndonPlatform EndonSoc`). Create a Cognito user, sign in,
   and screenshot the dashboard and an incident page.
3. Call `GET /api/summary` with the Cognito bearer token; screenshot the JSON.
4. Show that an unauthenticated request to the API returns `401`, proving the gate.
5. Redact the account ID before publishing.
