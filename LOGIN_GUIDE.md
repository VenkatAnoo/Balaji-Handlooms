# Separate admin and worker login

Start backend in `backend`: `python -m pip install -r requirements.txt` then `python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000`.
Start frontend in `frontend`: `npm install` then `npm run dev`.

Open http://localhost:5173/worker/login for workers or http://localhost:5173/admin/login for admins. Both show a role selector. The API verifies the selected role, so a worker login cannot be used for an admin account. Successful sign-in routes to `/worker/dashboard` or `/admin/dashboard`. API permissions remain enforced by FastAPI.

Initial demo accounts on a new database: admin1 / admin2, worker1 through worker10, all with initial password `ChangeMe@123`. Change passwords before production use.

The uploaded SQLite database was deliberately excluded from this ZIP to avoid redistributing live user/business data. Back up and copy your existing `backend/saree_business.db` into the extracted backend folder if you want to retain existing data.

Security: change the default JWT secret, configure secure email/SMS OTP providers before using password recovery, and deploy behind HTTPS.
