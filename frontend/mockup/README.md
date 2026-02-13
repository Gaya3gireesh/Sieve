# Sentinel Dashboard Mockup (Next.js)

This folder is a frontend structure mockup for the Sentinel owner dashboard.
It expects the FastAPI backend endpoints implemented in `app/main.py`:

- `GET /api/dashboard/stats`
- `GET /api/prs/queue`
- `GET /api/prs/reviewed`
- `GET /api/prs/spam-closed`
- `GET /api/prs/{scan_id}`

## Suggested placement in a real Next.js app

- Move `app/dashboard/page.tsx` into your Next app's `app/dashboard/page.tsx`.
- Move `components/*` into your app's component directory.
- Move `lib/api.ts` and `types.ts` into shared frontend utilities.

## Environment

Use a public backend URL in your frontend env:

```bash
NEXT_PUBLIC_SENTINEL_API_BASE=http://127.0.0.1:8000
```
