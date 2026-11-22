# SareeFlow — Full-Stack Saree Business Manager

A responsive React + FastAPI + SQLite web application for saree makers, inventory, workers, and sales.

## Features

- **Two pre-created admin accounts** with full visibility, product editing, transaction editing/deletion, user management and audit history.
- **Ten pre-created worker accounts**; each worker sees their own sales and collections, can create saree products, record maker collections, and record sales.
- **Saree inventory**: product catalog, SKU, category, unit price, collected count, sold count, and remaining count.
- **Collections**: record saree, maker name, worker, quantity and notes.
- **Sales**: record saree, quantity, total amount, payment type (cash / UPI / online), optional transaction ID and notes.
- **Live dashboards**: counts, revenue, payment breakdown and revenue chart.
- **Validation**: prevents selling more than collected; editing/deleting records cannot make inventory negative.
- **Security**: hashed passwords (Argon2), signed expiring access tokens, server-side roles, SQL parameter binding, and change audit log.
- **SQLite**: completely free, runs locally with no database server. Created automatically on first backend start.

## Folder structure

```text
saree-business-app/
├── backend/
│   ├── main.py                 # FastAPI, SQLite schema and API routes
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       └── styles.css
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or newer
- Node.js 18 or newer (Node.js 20+ recommended)

## 1. Start the backend

In a terminal:

```bash
cd saree-business-app/backend
python -m venv .venv
```

Activate virtual environment:

- **Windows:** `.venv\Scripts\activate`
- **macOS/Linux:** `source .venv/bin/activate`

Then:

```bash
pip install -r requirements.txt
```

Copy `.env.example` to `.env`. Set `SECRET_KEY` to a long random string. For local testing, the default development secret works, but **never use it on a public server**.

```bash
uvicorn main:app --reload --port 8000
```

API documentation: http://localhost:8000/docs

## 2. Start the frontend

In a second terminal:

```bash
cd saree-business-app/frontend
npm install
npm run dev
```

Open **http://localhost:5173** in your browser.

## Initial accounts

All 12 accounts are created automatically on the first startup of a fresh database:

| Role | Usernames | Initial password |
| --- | --- | --- |
| Admin | `admin1`, `admin2` | `ChangeMe@123` |
| Worker | `worker1` through `worker10` | `ChangeMe@123` |

**Immediately change all default passwords** via Team Members → Edit (admins can change any account password). These are starter credentials, not safe production passwords. Do not expose this app publicly with default credentials.

## Typical workflow

1. Log in as an admin or worker.
2. Add a saree in **Saree Catalog** (for example, Kanchipuram Silk, SKU `SILK-001`).
3. Open **Collections**, click **Record collection**, select saree, enter maker name and collected quantity.
4. Open **Sales & Payments**, click **Record sale**, select saree, quantity, total selling amount, and payment method. For UPI/online, transaction ID is optional.
5. Dashboard updates automatically. Remaining stock = total collected − total sold.
6. Admins can edit sarees, change any collection or sale, delete transaction records, manage users, and view the audit trail.

## Role permissions

| Action | Admin | Worker |
| --- | --- | --- |
| View all workers' records | Yes | No, only own records |
| View business-wide dashboard | Yes | No, own activity only |
| Add saree catalog item | Yes | Yes |
| Edit catalog item | Yes | No |
| Add collection or sale | Yes (assign worker) | Yes (own account) |
| Edit/delete collection or sale | Yes | No |
| Add/edit/deactivate users | Yes | No |
| View audit log | Yes | No |

**Important:** Workers can see overall product stock in the catalog (to avoid overselling), but only their own entries and totals. Admins see business-wide totals.

## API routes

- `POST /api/auth/login`, `GET /api/auth/me`
- `GET /api/dashboard`
- `GET /api/sarees`, `POST /api/sarees`, `PATCH /api/sarees/{id}`
- `GET /api/entries`, `POST /api/entries`, `PATCH /api/entries/{id}`, `DELETE /api/entries/{id}`
- `GET /api/users`, `POST /api/users`, `PATCH /api/users/{id}`
- `GET /api/audit`, `GET /api/health`

## Deployment and production notes

This is a functional **starter application**, not a completed enterprise deployment. Before public use: set a strong unique `SECRET_KEY`, reset seeded passwords, use HTTPS and secure hosting, configure CORS for your actual frontend domain, add automated backups, rate-limiting and login lockout, and consider PostgreSQL for larger multi-user deployments. SQLite is suitable for a small team and single backend instance; keep the database on persistent storage. For real financial bookkeeping, store monetary values as integer paise or decimal types instead of floating-point amounts. Add tests, monitoring, password-reset flows, and deployment CI before relying on it for critical operations.

**Note:** Cash/UPI/online are payment *record types*, not payment gateway integrations. The app does not transfer money or validate UPI transactions.

## SareeFlow V2 — makers and password recovery

New sections: Saree Makers, Maker Orders, Maker Deliveries, and Change Password. Add each maker (up to 100 or more), create orders by maker and saree design, and record partial deliveries. Remaining maker obligation is `ordered - delivered`. Delivery recording automatically adds a collected inventory entry, so **do not also enter the same delivery manually under Collections**. Admins see all deliveries; workers see their own delivery log. Maker/order totals are visible to both roles. Makers and orders may be created by workers; only admins may edit makers.

Existing SQLite data is migrated automatically (new tables and contact fields). **Back up `backend/saree_business.db` before upgrading.** Admins should add verified recovery email/mobile contact details for each user under Team Members. OTP email needs SMTP settings in `backend/.env`; for Gmail use an app password, not your normal Gmail password. SMS needs Twilio credentials. OTP reset does not work until a provider is configured and the user has a registered contact. Password changes while signed in require the current password. OTP expires after 5 minutes with 5 attempts and a 60-second request cooldown. For public deployment add perimeter rate limiting, stronger session invalidation, HTTPS and backup monitoring.


## V3 — Separate dashboards and daily editing

- Admin login opens the **Admin Workspace** with company-wide dashboard, user management, maker management, reports, and audit log.
- Worker login opens the **Worker Workspace** with today's delivered and sold saree counts, maker pending quantities, remaining inventory, and daily action buttons.
- Workers can edit **their own records created today (UTC)**. Older entries and other workers' records are read-only. Admins can edit entries from any date.
- Workers can edit today's maker delivery quantity via **Maker Deliveries → Edit**. The linked collection entry updates atomically, and the backend validates maker-order limits and remaining inventory.
- Remaining inventory and pending deliveries are computed from underlying transactions; they are not editable as independent totals.
- Password recovery via email/SMS requires provider configuration described above.
- For existing deployments, back up `backend/saree_business.db` before replacing application code.
- This is a local development build; test workflows and configure production security before public deployment.

## V4 — Add saree collections by name

In either dashboard select **Add Saree Collection**. Enter saree name, unique SKU, saree type, quantity received, price per saree, and a registered maker. Admins also select the worker to credit; worker accounts automatically record their own collections. Save creates both the saree catalog record and initial collection in one database transaction. Stock appears in Saree Catalog and is available for sale. Register the maker under **Makers** before using this form.

The initial collection is recorded in the general inventory ledger. It does not automatically fulfill a maker order; for ordered quantities and pending maker balances, use Maker Orders and Maker Deliveries separately. Avoid recording the same physical delivery in both collection workflows or inventory will be double-counted.
