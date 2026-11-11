# 🧪 Panduan Simulasi Makmal: OAuth Consent Grant di Microsoft Entra ID

Panduan ini menerangkan cara menjana telemetri **`Consent to application`** secara selamat di dalam *tenant* ujian Microsoft Entra ID anda tanpa memerlukan pelayan luaran. Tujuan utama adalah untuk menghasilkan log sebenar di dalam `SigninLogs` dan `AuditLogs` untuk dianalisis di dalam **Microsoft Sentinel**.

---

## 📋 Prasyarat Makmal
1. Akses kepada **Microsoft Entra ID** (langganan ujian Azure / M365 Developer Tenant).
2. **Microsoft Sentinel** telah disambungkan dengan *Data Connector* **Microsoft Entra ID** (`SigninLogs`, `AuditLogs`, `NonInteractiveUserSignInLogs`).
3. Dua akaun di dalam lab:
   - **Akaun Pentadbir (Global/App Admin):** Untuk mendaftarkan aplikasi ujian.
   - **Akaun Pengguna Biasa (Ujian Mangsa):** Contohnya `user.test@domainanda.onmicrosoft.com` dengan MFA diaktifkan.

---

## 🛠️ Langkah demi Langkah Simulasi

### Langkah 1: Semak Tetapan "User Consent" (Sementara Untuk Lab)
Agar pengguna ujian boleh meluluskan aplikasi semasa simulasi:
1. Log masuk ke [Microsoft Entra Admin Center](https://entra.microsoft.com).
2. Navigasi ke **Identity** $\rightarrow$ **Applications** $\rightarrow$ **Enterprise applications** $\rightarrow$ **Consent and permissions** $\rightarrow$ **User consent settings**.
3. Di bawah **User consent for applications**, pilih **Allow user consent for apps** untuk tujuan simulasi ini.
   > **Nota Keselamatan:** Selepas tamat sesi lab, kembalikan tetapan ini kepada *Do not allow user consent* atau *Allow user consent for apps from verified publishers* sebagai amalan pengerasan (*hardening*).

---

### Langkah 2: Daftar Aplikasi Ujian ("Mock OAuth App")
1. Navigasi ke **Identity** $\rightarrow$ **Applications** $\rightarrow$ **App registrations** $\rightarrow$ klik **New registration**.
2. Isi maklumat berikut:
   - **Name:** `Cloud-PDF-Reader-Simulation`
   - **Supported account types:** *Accounts in this organizational directory only (Single tenant)* (atau *Multitenant*).
   - **Redirect URI:** Pilih platform **Web** dan masukkan `https://localhost`.
3. Klik **Register**.
4. Pada halaman **Overview** aplikasi tersebut, salin:
   - **Application (client) ID**
   - **Directory (tenant) ID**

---

### Langkah 3: Konfigurasi Kebenaran API (Delegated Permissions)
1. Di dalam menu aplikasi `Cloud-PDF-Reader-Simulation`, pilih **API permissions** $\rightarrow$ klik **Add a permission**.
2. Pilih **Microsoft Graph** $\rightarrow$ **Delegated permissions**.
3. Cari dan tandakan kebenaran berikut (yang kerap menjadi sasaran penyerang dalam kes BEC):
   - `openid` & `offline_access`
   - `User.Read`
   - `Mail.ReadWrite`
   - `Files.ReadWrite.All`
4. Klik **Add permissions**.
   > ⚠️ **Penting:** **JANGAN** klik butang *"Grant admin consent for..."* di portal ini. Kita mahu mensimulasikan pengguna biasa yang menekan butang "Accept" pada skrin kebenaran OAuth.

---

### Langkah 4: Cetuskan Aliran Kebenaran Pengguna (Simulasi Mangsa)
1. Buka tetingkap pelayar baharu dalam mod **InPrivate / Incognito**.
2. Gantikan `<TENANT_ID>` dan `<CLIENT_ID>` dalam URL OAuth2 rasmi di bawah dengan nilai daripada Langkah 2:

```text
https://login.microsoftonline.com/<TENANT_ID>/oauth2/v2.0/authorize?client_id=<CLIENT_ID>&response_type=code&redirect_uri=https://localhost&response_mode=query&scope=openid%20offline_access%20Mail.ReadWrite%20Files.ReadWrite.All&state=simulation01
```

3. Layari URL tersebut dan log masuk menggunakan **Akaun Pengguna Biasa** (`user.test@...`).
4. Lengkapkan pengesahan **MFA** seperti biasa.
5. Anda akan melihat tetingkap **"Permissions requested"** daripada aplikasi `Cloud-PDF-Reader-Simulation`.
6. Klik **Accept**.
7. Pelayar akan cuba membuka `https://localhost/?code=...` dan memaparkan ralat tidak dapat bersambung—ini adalah normal kerana tiada pelayan web tempatan dipasang, tetapi **Microsoft Entra ID telah pun meluluskan kebenaran tersebut dan menjana log audit!**

---

## 🧹 Langkah Pembersihan Lab (Cleanup)
Selepas anda selesai menyemak log di Microsoft Sentinel:
1. Pergi ke **Entra Admin Center** $\rightarrow$ **Enterprise applications** $\rightarrow$ cari `Cloud-PDF-Reader-Simulation` $\rightarrow$ **Properties** $\rightarrow$ klik **Delete**.
2. Pergi ke **App registrations** $\rightarrow$ cari `Cloud-PDF-Reader-Simulation` $\rightarrow$ klik **Delete**.
3. Kembalikan tetapan **User consent settings** kepada keadaan asal yang selamat.
