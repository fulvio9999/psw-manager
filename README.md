# PswManager

Password manager self-hosted con FastAPI, UI web completa, 2FA (TOTP) e SQLite.

## Avvio locale

```bash
cd backend
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Apri `http://localhost:8000`.

## Docker + Nginx con TLS

1. Metti i certificati in `nginx/certs`:
   - `fullchain.pem`
   - `privkey.pem`
2. Avvia:
```bash
docker compose up -d --build
```

L'app risponde su `https://<tuo-dominio>`.

## Note

- Le credenziali sono cifrate con una chiave derivata dalla password utente.
- Le sessioni sono in memoria: al riavvio del container dovrai rifare il login.
