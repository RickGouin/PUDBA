# PUDBA

Polarforge Universal Database Backup Assistant is a self-contained web UI for creating and managing MySQL/MariaDB backups using native tools, with support for gzip compression, retention pruning, restore support, and basic job management.
---

### Backup and Restore
- Create full database backups or backups limited to selected tables.
- Uses `mysqldump` (or `mariadb-dump` if available).
- Supports gzip compression if `gzip` is available.
- Stores backups under a per-database directory within the configured backup folder.
- Retention pruning (delete backups older than `retention_days`).
- Restore from a `.sql` or `.sql.gz` backup file using `mysql` (or `mariadb`).
- Create scheduled backup jobs (hourly/daily/weekly/monthly) which are run via cron.
- Manage PUDBA cron jobs.

### Notes
- Simple username/password authentication stored as hashes in `config.php` (configured on first run).
- CSRF token checks for state-changing POST actions.
- Download/restore path traversal protection.
- Command logging with password masking (password passed via `MYSQL_PWD`).

---

## Requirements

### Runtime
- PHP running under a web server.
- PHP CLI for cron and CLI usage.

### PHP configuration
- Sessions enabled.
- `proc_open` enabled.
- File write access to configured directories.

### System binaries
- `mysqldump` or `mariadb-dump`
- `mysql` or `mariadb`
- `gzip` / `gunzip` (optional)
- `crontab` (for cron features)

---

## Installation

1. Upload all files to a folder on your server.
2. Visit that folder in a browser.
4. Complete initial authentication setup.
5. Add database connections via the UI.
6. Optionally configure backup jobs.

---

## Usage (Web UI)

### Backups
- Select a connection and database.
- Choose full database or selected tables.
- Run backup and monitor status.
- Logs are written per execution.

### Restore
- Select a backup file.
- Confirm restore action.
- Database contents will be overwritten.

### Cron Jobs
- Create hourly/daily/weekly/monthly jobs.
- Jobs are tagged and managed automatically.
- Jobs can be run or deleted from the UI.

---

## FAQ

**Where are backups stored?**  
In the configured backup_dir/<database>/.

**Why aren't my backups being compressed?**  
The tool uses gzip, which must be installed and available on your server.

**Why don’t cron jobs work?**  
Your host or server may restrict crontab usage.

**Does this support other databases?**  
Today, there is support for MySQL and MariaDB only.

---

## License

This software is licensed under the GPLv3 available here: https://www.gnu.org/licenses/gpl-3.0.en.html#license-text
