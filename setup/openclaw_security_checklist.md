# OpenClaw Security Checklist (Host & Infrastructure)

Этот чек-лист описывает критические шаги для обеспечения безопасности хоста (VPS), контейнеров и самой инсталляции OpenClaw.

## 🛡️ 1. Infrastructure Hardening (SSH & OS)
- [x] **SSH Port:** Использовать нестандартный порт (2244).
- [x] **SSH Auth:** Отключить вход по паролю (PasswordAuthentication no).
- [x] **SSH Access:** Ограничить вход только для root (AllowUsers root).
- [x] **Fail2ban:** Установлен и активен (включая nginx-http-auth, nginx-botsearch).
- [x] **UFW Firewall:** Активен, закрыты порты 5005, 8065, 3100.
- [x] **Updates:** Настроить unattended-upgrades (таймер активен).
- [x] **Ubuntu User:** Пользователь заблокирован, shell=nologin, удален из sudo/adm/lxd.

## 📦 2. Docker & Container Security
- [x] **Privileged Mode:** Удален (privileged: false).
- [x] **Capabilities:** Добавлен CAP_SYS_ADMIN (для bwrap).
- [x] **Limits:** Установлены ресурсы (2 CPU, 4GB RAM, 512 PIDs).
- [x] **Sandbox:** Внедрен bubblewrap (bwrap) для изоляции всех агентов.
- [x] **No New Privs:** Включен в docker-compose.yml.
- [x] **Firewall (DOCKER-USER):** Внедрена цепочка DOCKER-USER с LOG и DROP.
- [x] **Service:** Создан docker-security-rules.service (PartOf=docker.service).

## 🔑 3. Secret Management
- [x] **No Hardcoded Keys:** Ключи вынесены в .env или Infisical.
- [x] **Vault:** Использование vault.sh (права 700).
- [x] **Backup Passphrase:** Хранится в /root/.backup_passphrase (права 400).

## 💾 5. Backups & Recovery
- [x] **GPG Encryption:** Все бэкапы (и логи) шифруются симметрично через GPG.
- [x] **Cleanup:** Исправлен паттерн удаления старых бэкапов (храним baseline).
- [x] **Offsite:** Настроен rclone (b2-backup) для выгрузки в Backblaze B2.

---
*Документ обновлен: 19 Апреля 2026*
ok