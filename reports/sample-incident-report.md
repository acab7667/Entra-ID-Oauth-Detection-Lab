# 📄 Laporan Siasatan Insiden Keselamatan (SOC Incident Report)

| Maklumat Kes | Butiran |
| :--- | :--- |
| **ID Insiden** | `INC-2026-1111-042` |
| **Tajuk Insiden** | Kelulusan Aplikasi OAuth Mencurigakan (*Illicit Consent Grant*) — `Cloud-PDF-Reader-Simulation` |
| **Tarikh & Masa Dikesan** | 11 November 2026, 05:10 UTC (13:10 MYT) |
| **Tahap Keterukan (Severity)** | **High (Tinggi)** |
| **Status** | **Closed — True Positive (Lab Simulation)** |
| **Pengguna Terjejas** | `ahmad.albab@contoso-lab.onmicrosoft.com` (Jabatan Kewangan) |
| **Penganalisis Bertugas** | SOC L1 / L2 & Detection Engineer |

---

## 1. Ringkasan Eksekutif (Executive Summary)
Pada **11 November 2026 jam 05:10 UTC**, Microsoft Sentinel mencetuskan amaran berkeutamaan tinggi melalui peraturan analitik **`Microsoft Entra ID - Suspicious OAuth Application Consent Grant`**. Siasatan mendapati pengguna `ahmad.albab@contoso-lab.onmicrosoft.com` telah meluluskan satu aplikasi pihak ketiga bernama **`Cloud-PDF-Reader-Simulation`** yang meminta kebenaran kritikal `Mail.ReadWrite`, `Files.ReadWrite.All`, dan `offline_access`.

Walaupun pengesahan MFA telah berjaya dilakukan oleh pengguna semasa log masuk, kelulusan ini membolehkan aplikasi tersebut mengakses e-mel dan fail OneDrive pengguna secara berterusan melalui token OAuth tanpa memerlukan MFA tambahan. Pasukan SOC telah menyahaktifkan *Service Principal* aplikasi berkenaan dan membatalkan semua token akses yang berkaitan.

---

## 2. Garis Masa Kejadian (Incident Timeline — UTC)

| Masa (UTC) | Sumber Log | Peristiwa (Event) |
| :--- | :--- | :--- |
| `05:09:58` | `SigninLogs` | Pengguna `ahmad.albab@...` memulakan log masuk interaktif ke aplikasi `Cloud-PDF-Reader-Simulation` dari IP `203.0.113.45` dan meluluskan cabaran MFA (`CorrelationId: a1b2c3d4-9999-4444-8888-e5f6g7h8i9j0`). |
| `05:10:25` | `AuditLogs` | Peristiwa `Add service principal` dan `Consent to application` direkodkan. Pengguna memberikan kebenaran `openid offline_access User.Read Mail.ReadWrite Files.ReadWrite.All`. |
| `05:15:00` | `Sentinel` | Peraturan pengesanan KQL mencetuskan insiden `INC-2026-1111-042`. |
| `05:18:30` | `SOC L1` | Penganalisis L1 melakukan *triage*, mengesahkan `IsAdminConsent = False`, dan menaikkan kes kepada SOC L2. |
| `05:25:10` | `SOC L2` | Siasatan *Blast Radius* mengesahkan tiada pengguna lain terjejas. *Service Principal* dinyahaktifkan serta-merta. |

---

## 3. Penemuan Teknikal & Analisis Bukti (Technical Findings)

### A. Analisis `AuditLogs` (`Consent to application`)
Daripada rekod JSON `TargetResources`, pasukan SOC mengenal pasti artifak berikut:
- **Nama Aplikasi:** `Cloud-PDF-Reader-Simulation`
- **Service Principal ID:** `99999999-aaaa-bbbb-cccc-dddddddddddd`
- **App ID (Client ID):** `77777777-1234-5678-90ab-cccccccccccc`
- **Status Admin Consent:** `False` (Diluluskan oleh pengguna sendiri)
- **Skop Kebenaran:** `openid offline_access User.Read Mail.ReadWrite Files.ReadWrite.All`

### B. Analisis *Blast Radius* & Pasca-Kompromi
- Carian merentas 30 hari di dalam `AuditLogs` mengesahkan hanya **1 akaun pengguna** (`ahmad.albab@...`) telah meluluskan aplikasi ini.
- Semakan `AADNonInteractiveUserSignInLogs` menunjukkan tiada muat turun data pukal atau penciptaan peraturan peti masuk (`New-InboxRule`) sempat berlaku sebelum aplikasi disekat.

---

## 4. Tindakan Pembendungan & Pemulihan (Containment & Remediation)
1. **Penyahaktifan Aplikasi:** Status *Enabled for users to sign-in* bagi `Cloud-PDF-Reader-Simulation` di bawah *Enterprise Applications* telah ditukar kepada **No**.
2. **Pembatalan Token OAuth:** Rekod `OAuth2PermissionGrant` telah dipadamkan sepenuhnya daripada Microsoft Entra ID.
3. **Pembatalan Sesi Pengguna:** Arahan `Revoke-MgUserSignInSession` telah dijalankan ke atas akaun `ahmad.albab@contoso-lab.onmicrosoft.com` untuk memastikan semua *Refresh Token* sedia ada terbatal.

---

## 5. Cadangan Penambahbaikan (Lessons Learned & Hardening)
1. **Kawalan Kelulusan Pengguna (User Consent Governance):** Mengubah dasar Microsoft Entra ID supaya pengguna biasa tidak lagi boleh meluluskan aplikasi yang meminta kebenaran melampaui `User.Read`, dan mengaktifkan aliran kerja **Admin Consent Workflow**.
2. **Penalaan Pengesanan (Detection Tuning):** Mengekalkan peraturan KQL sedia ada di Microsoft Sentinel dengan pemetaan entiti automatik pada `InitiatedByUser`, `IpAddress`, dan `AppDisplayName`.
