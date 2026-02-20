# 🚀 Розгортання на Production

## Переклад на PostgreSQL

### 1. Встановлення PostgreSQL

**На Windows:**
1. Завантажити PostgreSQL 14+ з https://www.postgresql.org/download/windows/
2. Встановити з паролем для користувача `postgres`
3. Запам'ятати налаштування

### 2. Створення бази даних

```sql
-- Підключитися як postgres
CREATE DATABASE vouchers_db;
CREATE USER vouchers_user WITH PASSWORD 'your_secure_password';
ALTER ROLE vouchers_user SET client_encoding TO 'utf8';
ALTER ROLE vouchers_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE vouchers_user SET default_transaction_deferrable TO on;
ALTER ROLE vouchers_user SET timezone TO 'Europe/Kyiv';
GRANT ALL PRIVILEGES ON DATABASE vouchers_db TO vouchers_user;
```

### 3. Оновлення `.env`

```env
NODE_ENV=production
PORT=3000
DATABASE_URL=postgresql://vouchers_user:your_secure_password@localhost:5432/vouchers_db
JWT_SECRET=change-this-to-very-secure-random-string
BCRYPT_ROUNDS=12
```

### 4. Запуск на сервері

```bash
cd c:\Mafis\backend
npm start
```

Сервер буде слухати на http://localhost:3000

## Docker розгортання

### Dockerfile

```dockerfile
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  # Backend
  backend:
    build: ./backend
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: production
      PORT: 3000
      DATABASE_URL: postgresql://vouchers_user:password@db:5432/vouchers_db
      JWT_SECRET: your-secret-key
    depends_on:
      - db
    networks:
      - vouchers-network

  # PostgreSQL
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: vouchers_db
      POSTGRES_USER: vouchers_user
      POSTGRES_PASSWORD: password
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - vouchers-network

  # Frontend (optional - можна використовувати nginx)
  frontend:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./frontend/build:/usr/share/nginx/html
    networks:
      - vouchers-network

volumes:
  pgdata:

networks:
  vouchers-network:
```

**Запуск:**
```bash
docker-compose up -d
```

## Nginx конфігурація (Production)

```nginx
upstream backend {
    server localhost:3000;
}

server {
    listen 80;
    server_name vochers.school.ua;  # Замінити на ваш домен

    # Редирект на HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vouchers.school.ua;

    # SSL сертифікати
    ssl_certificate /etc/ssl/certs/certificate.crt;
    ssl_certificate_key /etc/ssl/private/private.key;

    # Безпека
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Frontend
    root /var/www/vouchers/frontend/build;
    
    location / {
        try_files $uri $uri/ /index.html;
    }

    # API proxy
    location /api/ {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }

    # Статичні файли
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Гроші логування
    access_log /var/log/nginx/vouchers_access.log;
    error_log /var/log/nginx/vouchers_error.log;
}
```

## Моніторинг на Production

### PM2 (процес менеджер)

```bash
# Встановлення
npm install -g pm2

# Запуск
pm2 start backend/server.js --name "vouchers-api"

# Моніторинг
pm2 monit

# Логи
pm2 logs vouchers-api

# Автозапуск при перезавантаженні
pm2 startup
pm2 save
```

### systemd служба (альтернатива)

Створіть `/etc/systemd/system/vouchers.service`:

```ini
[Unit]
Description=School Vouchers System
After=network.target

[Service]
Type=simple
User=vouchers
WorkingDirectory=/opt/vouchers
ExecStart=/usr/bin/node /opt/vouchers/backend/server.js
Restart=always
RestartSec=10

Environment="NODE_ENV=production"
Environment="PORT=3000"
Environment="DATABASE_URL=postgresql://vouchers_user:password@localhost:5432/vouchers_db"

[Install]
WantedBy=multi-user.target
```

```bash
# Активація
sudo systemctl enable vouchers
sudo systemctl start vouchers
sudo systemctl status vouchers
```

## Резервні копії

### Автоматична резервна копія БД

```bash
#!/bin/bash
# backup.sh - поставити в cron

BACKUP_DIR="/backups/vouchers"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# PostgreSQL backup
pg_dump -U vouchers_user -h localhost vouchers_db | gzip > $BACKUP_DIR/vouchers_db_$DATE.sql.gz

# Залишити тільки останні 30 днів
find $BACKUP_DIR -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/vouchers_db_$DATE.sql.gz"
```

```bash
# Додати в crontab (3 ночі по UTC)
0 3 * * * /opt/vouchers/backup.sh
```

## Відновлення з резервної копії

```bash
# Розпакувати та відновити
gunzip < vouchers_db_20260215_030000.sql.gz | psql -U vouchers_user -d vouchers_db
```

## Масштабування

### Горизонтальне масштабування (балансування навантаження)

1. Запустити кілька копій backend процесів
2. Налаштувати nginx для розподілу запитів:

```nginx
upstream backends {
    server localhost:3001;
    server localhost:3002;
    server localhost:3003;
}

location /api/ {
    proxy_pass http://backends;
}
```

3. Використовувати Redis для сесій (опціонально)

## Моніторинг та Логування

### Elkstack (Elasticsearch + Logstash + Kibana)

Інтеграціяログів для аналізу та моніторингу

---

**Система готова до production використання!** 🎉
