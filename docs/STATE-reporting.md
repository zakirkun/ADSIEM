# STATE — Reporting Feature

Last updated: 2026-10-20
Branch: nightmare-c0de
Scope: SIEM reporting (detail periode, per-kasus, per-agen)

## Status

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 1 | `alerts.case_id` column (server-api + worker models) | DONE | `models.py`, `worker/worker/models.py` |
| 2 | Migration helper `_migrate_alert_case_id` + backfill dari `cases.alert_id` | DONE | `app/main.py:421` |
| 3 | Worker mengisi `case_id` (case baru, campaign join, digest) | DONE | `worker/worker/ai_analyst.py` |
| 4 | Backfill historis via `ioc_keys` IP | DONE | `app/services/alert_case_backfill.py` |
| 5 | Dataset builder 3 scope | DONE | `app/services/report_data.py` |
| 6 | Renderer PDF (layout eksekutif + glosarium) | DONE | `app/services/report_pdf.py` |
| 7 | Renderer Excel multi-sheet | DONE | `app/services/report_excel.py` |
| 8 | Endpoint `/api/reports/build` + `/options` | DONE | `app/api/routes/reports.py` |
| 9 | Skema request `ReportRequest` | DONE | `app/schemas/schemas.py` |
| 10 | UI: tab, selector kasus/agen, format, error ramah | DONE | `dashboard/src/pages/ReportsPage.tsx` |
| 11 | Tipe bersama frontend (tanpa `any`) | DONE | `dashboard/src/types/index.ts` |
| 12 | Unit test dataset + renderer | DONE | `tests/server-api/test_report_data.py` (27) |
| 13 | Integration test dataset (Postgres) | DONE | `tests/server-api/test_report_build.int.py` (9) |
| 14 | Unit test backfill (`parse_excluded_ips`) | DONE | `tests/server-api/test_alert_case_backfill.py` (12) |
| 15 | Integration test backfill (Postgres) | DONE | `tests/server-api/test_alert_case_backfill.int.py` (7) |
| 16 | `openpyxl` di requirements | DONE | `server-api/requirements.txt` |

## Verification

```
pytest test_report_data.py test_report_build.int.py \
       test_alert_case_backfill.py test_alert_case_backfill.int.py   55 passed
ruff check (new/changed files)                                       All checks passed
dashboard npm run build (tsc -b + vite)                              ✓ built
```

## Known Limitations

- **Backfill hanya untuk alert dengan `source_ip`.** Alert tanpa IP tidak bisa
  dicocokkan ke kasus lama; alert baru tetap akurat karena worker mengisi `case_id`.
- **Backfill berjalan sekali**, ditandai `platform_settings.alert_case_id_ioc_backfill_at`.
  Untuk menjalankan ulang, hapus baris setting itu.
- **IP bersama (NAT/proxy)** dapat menarik alert ke kasus yang salah. Mitigasi:
  tambahkan IP tersebut ke setting `case_ioc_exclusions`.
- **Narasi AI opsional**; tanpa 9router laporan tetap lengkap, hanya tanpa ringkasan naratif.
- **Batas**: 366 hari per laporan periode, 50 kasus per laporan kasus.

## Not Done (butuh keputusan)

- [ ] Kirim laporan terjadwal lewat email (worker `report_sender.py` masih digest mingguan terpisah)
- [ ] Simpan riwayat laporan yang pernah dibuat
- [ ] Template laporan kustom per organisasi
