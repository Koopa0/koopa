# Database backup

Script and restore runbook live in `Koopa0/server` (`scripts/backup-db-r2.sh`,
`DISASTER-RECOVERY.md`); that repo is authoritative. This is the pointer.

## When
Daily 03:00 Asia/Taipei via VPS cron (`0 3 * * *`), installed by
`server/scripts/setup-cron.sh`. One run dumps `koopa0dev` and `trader`.

## Where
- Local: `~/backups/db/koopa0dev-<YYYYMMDD-HHMMSS>.sql.gz`, 7-day retention.
- Off-site: `s3://koopa0-dev/backups/koopa0dev-db/`, 7-day retention.
- Freshness: each success writes a node-exporter textfile metric; Grafana alert
  `db-backup-stale` pages Telegram once the newest success passes 26h.

## Restore
`DISASTER-RECOVERY.md` scenario A, steps 8–10: bring up postgres alone, fetch the
newest R2 object, then restore with both safety flags —
`gunzip -c … | psql -U koopa koopa0dev -v ON_ERROR_STOP=1 --single-transaction` —
and start the rest of the stack. The runbook's own command omits both; without
them psql exits 0 after a failed statement and leaves a partial schema.

## Drill
2026-07-10: the R2 object restored clean into a throwaway `pgvector:pg17`; all 18
tables matched the dump's own COPY counts (todos 42, contents 4, activity_events 446).
