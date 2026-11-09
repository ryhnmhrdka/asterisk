# PRD

# PRODUCT REQUIREMENTS DOCUMENT (PRD)

## Produk: Asterisk

**Tagline:** *Autonomous Pre-Production Code Defense, Supply-Chain Reachability & Security Audit Harness***Versi Dokumen:** 1.0 (Final Product Specification)**Kategori Kompetisi:** Penangkalan Siber (Deteksi, Pencegahan, dan Respons Ancaman Siber Sebelum/Saat Terjadi pada Fase Pra-Produksi)**Target Platform:** Multi-OS Single Static Binary (Linux, macOS, Windows) dengan Antarmuka **100% Full Interactive TUI****Status Dokumen:** Disetujui untuk Fase Engineering (Tersinkronisasi dengan TDD v2.0)

***

## 1. Ringkasan Eksekutif & Visi Produk

### 1.1 Visi Produk

Menjadi sistem **AI Agent Execution Harness** pertama yang menyatukan ketajaman analisis program deterministik (*Code Context Graph & Function-Level Reachability*) dengan kecerdasan koloni agen otonom yang adaptif di dalam satu antarmuka terminal interaktif (**Full-TUI Interactive Whiteboard**), guna memastikan **nol kerentanan (*****zero preventable vulnerabilities*****)** yang lolos dari komputer *developer* ke lingkungan produksi.

### 1.2 Deskripsi Singkat Produk

**Arterisk** adalah perkakas pertahanan dan audit keamanan kode pra-produksi (*Shift-Left DevSecOps*) berbentuk satu berkas biner mandiri berbasis Rust. Berbeda dengan pemindai statis tradisional yang membanjiri pengembang dengan ratusan peringatan palsu (*false positives*) atau *chatbot* AI yang sekadar menebak-nebak isi kode, Asterisk bekerja langsung di atas repositori *source code* lokal (Web App, Backend API, dan kode sumber Mobile/APK) dengan tiga pilar kekuatan utama:

1. **Deteksi Presisi Tinggi Bebas Sampah (*****Noise-Free Detection*****):** Memetakan grafik hubungan fungsi dan alur data secara deterministik sebelum dianalisis oleh Sub-Agent, serta memisahkan celah yang benar-benar terpanggil (*Reachable*) dari yang tidak berbahaya (*Unreachable*).
2. **Pencegahan Rantai Pasok & Rahasia (*****Proactive Prevention*****):** Menangkal masuknya paket *open-source* berbahaya (*malware/typosquatting*), menemukan *library* siluman (*phantom dependencies*), dan menyapu kebocoran kredensial hingga ke seluruh riwayat Git (`--git-logs`).
3. **Respons Penangkalan Otomatis Tanpa Merusak Aplikasi (*****Closed-Loop Auto-Hardening*****):** Membuktikan celah secara nyata lewat pembuatan *Security Unit Test* di dalam *sandbox* lokal, lalu menulis tambalan kode pengaman (*source code patch*) maupun tambalan pustaka pihak ketiga tanpa paksaan *upgrade* versi (*Local Dependency Hotfix*).

***

## 2. Latar Belakang Masalah & Analisis Gap Pasar

### 2.1 Empat Masalah Kritis di Industri Saat Ini (*Problem Statements*)

1. **Ledakan Kecepatan Kode vs Kelumpuhan Audit (*****Alert Fatigue*****):** Penggunaan AI *coding assistant* mempercepat penulisan kode berkali-kali lipat, namun alat SAST/SCA tradisional menghasilkan **68% hingga 78% alarm palsu (*****false positives*****)**. *Developer* akhirnya mengabaikan laporan keamanan karena kelelahan menyaring ratusan peringatan CVE pada fungsi *library* yang sebenarnya tidak pernah dipanggil oleh aplikasi mereka.
2. **Kebutaan Terhadap&#x20;*****Phantom Dependencies*****&#x20;& Malware Tanpa CVE:** Alat pemindai konvensional hanya membaca berkas manifest (`package.json`, `requirements.txt`), sehingga buta terhadap paket siluman yang langsung di-`import` di kode (*phantom dependencies*). Selain itu, \~40% paket *malware* di repositori publik tidak pernah memiliki nomor CVE dan langsung mengeksekusi skrip jahat saat proses instalasi berjalan.
3. **Dilema "Upgrade = Rusak" (*****Breaking Changes Dilemma*****):** Ketika ditemukan celah pada *library* pihak ketiga, solusi standar alat lama adalah menyuruh *developer* meng-*upgrade* versi paket. Di dunia nyata, *upgrade* versi sering kali merusak kompilasi aplikasi utama, sehingga celah keamanan dibiarkan terbuka berbulan-bulan.
4. **Risiko Privasi Kode &&#x20;*****Guardrail Refusal*****&#x20;pada AI Cloud:** Mengirimkan seluruh *source code* perusahaan yang belum rilis ke layanan AI Cloud berisiko melanggar kepatuhan privasi data, ditambah model komersial sering menolak (*refusal*) ketika diminta membuat skrip pengujian ketahanan keamanan.

### 2.2 Posisi Keunggulan Asterisk (*Competitive Positioning*)

| Dimensi Kemampuan                                        | Legacy SAST / SCA (Snyk / SonarQube) | AI Coding Assistant Biasa (Chat / Copilot) | Enterprise AppSec Cloud (AURI Endor Labs) | **Asterisk (Karya Ini)**                                           |
| -------------------------------------------------------- | ------------------------------------ | ------------------------------------------ | ----------------------------------------- | ------------------------------------------------------------------ |
| **Fokus Operasi**                                        | Peringatan pasif di CI/CD            | Asisten penulisan fitur                    | Platform SaaS Enterprise                  | **Local Pre-Production Defense Harness**                           |
| **Function-Level Reachability & Phantom Deps**           | Lemah / Hanya baca manifest          | Tidak ada (baca teks mentah)               | Sangat Kuat (Cloud Graph)                 | **Kuat (Local AST&#x20;****`GraphCore`****&#x20;Engine)**          |
| **Eliminasi False Positive**                             | Rendah (70%+ *noise*)                | Halusinasi tinggi                          | Agen Triage + Aturan Konteks              | **Agen Triage +&#x20;****`SECURITY.md`****&#x20;+ Uji Unit Lokal** |
| **Penambalan Tanpa Upgrade (*****Hotfix Backport*****)** | Tidak bisa (wajib *upgrade*)         | Saran teks generik                         | Endor Patches (Cloud Binary)              | **Autonomous Local&#x20;****`.patch`****&#x20;Generator**          |
| **Dukungan 100% Offline / Local LLM**                    | Tidak (Cloud-dependent)              | Tidak (Wajib Cloud API)                    | Terbatas                                  | **Penuh (****`Variatif Providers`****: Ollama / Cloud)**           |
| **Antarmuka Orkestrasi Visual**                          | Dashboard Web Kaku                   | Panel Chat Teks                            | Dashboard Web SaaS                        | **Full-TUI + Interactive Whiteboard Canvas**                       |

***

## 3. Target Pengguna & User Persona

| Persona                                                                    | Peran & Konteks Kerja                                                                                                  | Masalah Utama (*Pain Points*)                                                                                                                   | Solusi yang Diberikan **Asterisk**                                                                                                                                                 |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Persona 1: Raka —&#x20;*****Full-Stack & Mobile Developer***             | Menulis kode Web/API dan aplikasi Android (Kotlin/Flutter) setiap hari di terminal & IDE.                              | Malas menjalankan *scanner* karena lambat, harus buka *browser*, dan laporannya penuh alarm palsu yang merusak fokus *coding*.                  | Cukup ketik `/audit --diff` langsung di terminal sebelum `git commit`. Hasil keluar dalam <15 detik, bebas *false positive*, dan langsung disediakan tombol *merge patch*.         |
| **Persona 2: Dinda —&#x20;*****DevSecOps / AppSec Engineer***              | Bertanggung jawab memastikan aplikasi bebas celah sebelum rilis ke produksi dan lolos audit ISO/SOC2.                  | Kewalahan memeriksa ratusan PR, sulit melacak apakah CVE benar-benar *reachable*, dan butuh aturan keamanan kustom perusahaan.                  | Bisa menyuntikkan fakta arsitektur di `SECURITY.md`, membuat/mengimpor `.skill.md` kustom, memantau alur kerja Sub-Agent di kanvas TUI, dan mengunduh bukti audit *OpenTelemetry*. |
| **Persona 3: Bima —&#x20;*****Tech Lead di Industri Ketat (Fintech/Gov)*** | Mengelola repositori dengan aturan privasi ketat (*air-gapped* / dilarang kirim kode ke luar) dan dependensi kompleks. | Tidak boleh memakai AI Cloud karena *source code* bersifat rahasia, serta takut meng-*upgrade* *library* lama karena memicu *breaking changes*. | Menjalankan Asterisk dengan model lokal **Ollama**, serta menutup celah *library* pihak ketiga lewat fitur `/hotfix --no-upgrade`.                                                 |

***

## 4. Ruang Lingkup Produk (*In-Scope vs Out-of-Scope*)

Penegasan ruang lingkup ini memastikan produk **100% patuh pada kategori kompetisi Penangkalan Siber** dan fokus pada pengamanan tahap pengembangan lokal:

### 4.1 Di Dalam Ruang Lingkup (*In-Scope — Fokus Penangkalan Pra-Produksi*)

* **Audit & Pertahanan Source Code Lokal:** Bekerja murni pada direktori kode sumber lokal di komputer *developer* sebelum aplikasi di-*deploy*.
* **Cakupan Target Analisis Lokal:**
  1. *First-Party Source Code* (Web Frontend, Backend API, Microservices).
  2. *Pre-Build Mobile App Source* (Kode Kotlin/Java/Flutter, berkas `AndroidManifest.xml`, dan `build.gradle` sebelum dikompilasi menjadi APK).
  3. *Open-Source Supply Chain* (Dependensi langsung, transitif, *phantom dependencies*, serta deteksi *malware* paket pra-instalasi).
  4. *Git Repository History & Container Configs* (Seluruh riwayat *commit* Git lokal `--git-logs` untuk deteksi kebocoran *secret*, serta konfigurasi `Dockerfile` / `docker-compose.yml` lokal).
* **Pengujian Dinamis Terisolasi (*****Local Sandbox Execution*****):** Menjalankan *Security Unit Test* lokal terhadap fungsi kode di dalam ruang isolasi *Git Worktree* untuk membuktikan kerentanan sekaligus memverifikasi tambalan kode.

### 4.2 Di Luar Ruang Lingkup (*Out-of-Scope — Pembatas Etika & Hukum*)

* **Bukan Alat Serangan Jaringan Eksternal (*****No Remote Offensive Exploitation*****):** Produk ini **tidak** dirancang untuk melakukan pemindaian jaringan eksternal, menembus *firewall* server pihak ketiga, atau menyerang aplikasi web/API yang sudah berjalan di internet publik.
* **Tidak Menggunakan Browser/GUI Berat:** Seluruh pengalaman visual (termasuk kanvas *Whiteboard* *node-graph*) berjalan 100% di dalam antarmuka terminal (TUI).

***

## 5. Fitur Utama & Spesifikasi Kebutuhan Fungsional (*Functional Requirements*)

Setiap kebutuhan fungsional diberi kode **`FR-XX`** dengan tingkat prioritas **`P0`****&#x20;(Wajib untuk MVP/Demo Utama)** atau **`P1`****&#x20;(Fitur Penguat/Diferensiator Lomba)**.

### 5.1 Kelompok Fitur A: Pemetaan Konteks Deterministik & Orkestrasi Agen Adaptif

* **`FR-01`****&#x20;\[P0] Pemetaan&#x20;****`GraphCore`****&#x20;(Local Code Context Graph):**
  Sistem harus mampu memindai *source code* lokal menggunakan parser sintaks multi-bahasa untuk membangun peta hubungan antar-berkas, panggilan fungsi (*Call Graph*), dan aliran data input ke eksekusi sensitif (*Taint Flow*) sebelum memanggil model AI, sehingga memangkas pemakaian token hingga >80%.
* **`FR-02`****&#x20;\[P0] Injeksi Fakta Arsitektur via&#x20;****`SECURITY.md`****&#x20;(*****AI Context Rules*****):**
  Sistem harus membaca berkas `SECURITY.md` di akar proyek sebagai kebenaran mutlak (*ground truth*) mengenai arsitektur dan *middleware* keamanan proyek guna menekan alarm palsu.
* **`FR-03`****&#x20;\[P0] Pemijahan Sub-Agent Secara Organik (*****Organic Sub-Agent Spawning*****):**
  *Orchestrator* tidak boleh menggunakan daftar agen kaku, melainkan harus merakit dan meluncurkan *Sub-Agent* spesialis secara dinamis menyesuaikan tumpukan teknologi yang ditemukan pada proyek lokal, masing-masing dengan jendela konteks bersih (*clean context window*).
* **`FR-04`****&#x20;\[P0] Ekosistem 3-Tier Interactive Skills dengan&#x20;*****Progressive Disclosure*****:**
  1. Sistem harus memuat *header* YAML singkat dari berkas `.skill.md` saat inisialisasi dan baru memuat instruksi penuh secara *on-demand* ketika *Sub-Agent* menemukan indikasi celah terkait (*Progressive Disclosure*).
  2. Mendukung 3 tingkatan *skill*: **Tier-1 (Bawaan Pabrik)**, **Tier-2 (Kustomisasi Manual & Fitur&#x20;****`Import/Export`****&#x20;oleh Pengguna)**, serta **Tier-3 (Sintesis Otomatis oleh Orchestrator saat menganalisis pola kode unik proyek lokal)**.
* **`FR-05`****&#x20;\[P0] Multi-Model Smart Router (****`Variatif Providers`****&#x20;— Offline & Cloud):**
  Pengguna harus dapat memilih dan mengganti penyedia LLM secara fleksibel, baik berjalan **100% lokal/offline** (melalui **Ollama** atau **LM Studio**) maupun menggunakan API Cloud (Claude, OpenAI, Gemini, DeepSeek).

### 5.2 Kelompok Fitur B: Deteksi Pertahanan Kode, Rantai Pasok & Konfigurasi APK

* **`FR-06`****&#x20;\[P0] Pipeline Tri-Stage AI SAST & Mode Cepat&#x20;****`--diff-scope=local`****:**
  Menjalankan siklus 3 tahap (*Detection&#x20;**$\to$**&#x20;Auditable Triage&#x20;**$\to$**&#x20;Contextual Remediation*). Setiap temuan yang dinyatakan *True Positive* maupun *False Positive* wajib disertai alasan teknis tertulis yang dapat diaudit. Mendukung pemindaian penuh (`--full`) maupun pemindaian instan khusus baris kode yang baru diubah sebelum *commit* (`--diff-scope=local`).
* **`FR-07`****&#x20;\[P0] Analisis SCA dengan&#x20;*****Function-Level Reachability*****&#x20;&&#x20;*****Phantom Dependencies*****:**
  Sistem harus mendeteksi *library* yang di-`import` di kode sumber namun tidak tercatat di manifest (*Phantom Dependency*), serta melacak jalur panggilan fungsi untuk melabeli setiap CVE dengan status **`Reachable`**, **`Unreachable`**, atau **`Potentially Reachable`**.
* **`FR-08`****&#x20;\[P0] Deteksi & Validasi Semantik&#x20;*****Secrets*****&#x20;di Seluruh Riwayat Git (****`--git-logs`****):**
  Menyapu kode kerja saat ini dan seluruh riwayat *commit* di semua *branch* Git lokal untuk mendeteksi kebocoran kunci rahasia, lalu memvalidasi konteks kode di sekitarnya agar mampu membedakan kunci asli dari *dummy key* contoh pengujian.
* **`FR-09`****&#x20;\[P1] Perisai Paket Berbahaya Pra-Instalasi (*****Pre-Install Malware Shield*****):**
  Menganalisis paket baru sebelum/saat ditambahkan ke proyek untuk menangkal *typosquatting*, *dependency confusion*, serta skrip instalasi tersembunyi (*obfuscated&#x20;**`preinstall`**/**`postinstall`**&#x20;scripts*).
* **`FR-10`****&#x20;\[P1] Penjaga Kode Sumber APK Android & Konfigurasi Kontainer Lokal:**
  Mengaudit `AndroidManifest.xml`, `build.gradle`, dan kode Kotlin/Java/Flutter untuk mencegah kesalahan izin komponen (`android:exported`), *Intent spoofing*, dan *cleartext traffic* sebelum aplikasi dikompilasi menjadi APK, serta melacak *Code-to-Container Reachability* pada `Dockerfile` lokal.

### 5.3 Kelompok Fitur C: Respons Penangkalan Otomatis, Tata Kelola & Keamanan Internal

* **`FR-11`****&#x20;\[P0] Verifikasi&#x20;*****Security Unit-Test*****&#x20;Lokal &&#x20;*****Auto-Hardening*****&#x20;di Git Worktree:**
  Untuk setiap celah berstatus *Reachable*, *Sub-Agent* harus bekerja di dalam ruang isolasi **Git Worktree** untuk membuat skrip *Security Unit Test* lokal, menulis kode perbaikan (*auto-hardening patch*), dan menjalankan pengujian ulang hingga lulus 100% tanpa merusak kode asli pengembang.
* **`FR-12`****&#x20;\[P1] Penambalan Pustaka Lokal Tanpa Upgrade (*****Vendor Hotfix Backport*****):**
  Menyediakan perintah `/hotfix --no-upgrade` yang menambal langsung fungsi rentan di dalam kode *library* pihak ketiga secara lokal dan menghasilkan berkas `.patch` otomatis bagi tim yang menghindari *breaking changes*.
* **`FR-13`****&#x20;\[P0] Gerbang Izin Pra-Eksekusi,&#x20;*****Safe Outputs Gate*****&#x20;&&#x20;*****Immutable Audit Trail*****:**
  1. Memblokir mutlak akses berkas di luar folder proyek aktif (`Deny -> Ask -> Allow`) dan menangkal *Indirect Prompt Injection* melalui *Background Security Classifier*.
  2. Memeriksa ulang setiap kode tambalan buatan AI dengan aturan deterministik (*Safe Outputs*) sebelum diserahkan ke pengguna.
  3. Merekam seluruh jejak aktivitas agen ke dalam log *OpenTelemetry* (`audit_trail.jsonl`) untuk bukti kepatuhan audit.

***

## 6. Pengalaman Pengguna (UX) & Alur Interaksi Full-TUI

### 6.1 Desain Antarmuka Tiga Panel (*Full-TUI Split-Pane Architecture*)

Seluruh interaksi pengguna berlangsung di dalam satu layar terminal yang dibagi menjadi 3 area kerja terintegrasi:

1. **Panel Utama (Kiri — 60% Layar):&#x20;*****Interactive TUI Whiteboard Canvas***
   * Kanvas tanpa batas (*infinite canvas*) berbasis terminal yang dapat digeser (*pan*) dan diperbesar (*zoom*) menggunakan *mouse* maupun papan ketik (`h, j, k, l`).
   * Menampilkan kotak *Orchestrator*, pertumbuhan kotak *Sub-Agent* secara organik, peta jalur fungsi rentan (*Code Context Graph*), animasi panah aliran pesan antar-agen (*Braille edges*), serta percabangan pohon keputusan (*decision tree*) secara *live*.
2. **Panel Inspeksi (Kanan Atas — 40% Layar):&#x20;*****Node Inspector & Side-by-Side Diff Viewer***
   * Saat pengguna mengeklik salah satu kotak *node* di kanvas TUI, panel ini menampilkan detail kerja agen tersebut: alasan *Triage*, status *Security Unit Test*, dan perbandingan kode **Before vs After (*****Git Diff*****)** berwarna hijau/merah.
3. **Panel Komando (Kanan Bawah):&#x20;*****Steerable Slash-Command REPL***
   * Baris perintah interaktif dengan fitur *autocompletion* untuk menjalankan perintah `/init-sec`, `/audit`, `/reachability`, `/secrets`, `/shield`, `/patch`, `/hotfix`, `/skills`, `/mode`, `/todos`, dan `/doctor`.

### 6.2 Peta Perjalanan Pengguna (*End-to-End User Journey: Day 0 hingga Pre-Release*)

```
[Tahap 1: Inisialisasi (Day 0)]
Developer membuka terminal di folder proyek -> Ketik `/init-sec`
  └── Sistem memetakan Code Context Graph (<5 detik) & membuat draf `SECURITY.md`.

[Tahap 2: Audit Cepat Harian (Pre-Commit)]
Developer selesai menulis fitur baru -> Ketik `/audit --diff-scope=local`
  └── Kanvas TUI menampilkan Orchestrator melahirkan Sub-Agent secara organik.
  └── SAST & SCA memeriksa perubahan kode: 3 peringatan disaring otomatis oleh Triage Agent karena `Unreachable`, 1 celah SQLi dinyatakan `Reachable (True Positive)`.

[Tahap 3: Kemudi Visual & Penangkalan Otomatis (Auto-Hardening)]
Node SQLi menyala merah di kanvas TUI -> Developer klik Node tersebut atau ketik `/patch`
  └── Patcher Sub-Agent bekerja di Git Worktree: membuat Security Unit-Test, menulis kode Parameterized Query, menguji ulang hingga PASS, dan lulus gerbang Safe Outputs.
  └── Node berubah menjadi hijau. Developer melihat Git Diff di panel kanan -> Tekan `[Enter]` untuk menerapkan tambalan ke kode utama.

[Tahap 4: Sertifikasi Pra-Rilis (Compliance Export)]
Sebelum proyek di-build menjadi APK / di-deploy ke server -> Semua indikator di TUI hijau
  └── Sistem menghasilkan Laporan Eksekutif Penangkalan, bukti Reachability (VEX/SBOM ready), dan berkas `audit_trail.jsonl`.
```

***

## 7. User Stories & Acceptance Criteria

Tabel berikut mendefinisikan standar kelulusan fungsional yang wajib dipenuhi oleh tim *engineering* saat pengujian produk:

| ID        | User Story (Kisah Pengguna)                                                                                                                                                                                                                               | Acceptance Criteria (Kriteria Penerimaan Terukur)                                                                                                                                                                                                                                                                             |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **US-01** | Sebagai **Developer**, saya ingin menjalankan audit hanya pada perubahan kode terbaru sebelum melakukan *commit*, agar saya mendapat kepastian keamanan dalam hitungan detik tanpa menunggu pemindaian seluruh repositori.                                | 1. Perintah `/audit --diff-scope=local` hanya mem-parsing ulang berkas yang berubah beserta jalur fungsi yang terhubung.&#xA;2\. Waktu eksekusi untuk perubahan $\le 10$ berkas selesai dalam **$\le 15$****&#x20;detik**.&#xA;3\. Hasil langsung tampil di kanvas TUI.                                                       |
| **US-02** | Sebagai **AppSec Engineer**, saya ingin sistem memisahkan CVE pada *library* yang benar-benar dipanggil oleh aplikasi dari yang tidak pernah dipanggil, serta mendeteksi *phantom dependencies*, agar tim tidak membuang waktu mengurus peringatan palsu. | 1. Perintah `/reachability` berhasil menandai paket yang di-`import` di kode tetapi tidak ada di manifest sebagai `PHANTOM_DEP`.&#xA;2\. Setiap CVE memiliki label tegas (`REACHABLE`, `UNREACHABLE`, `POTENTIALLY_REACHABLE`) lengkap dengan bukti jalur pemanggilan fungsi (*call path JSON*).                              |
| **US-03** | Sebagai **Mobile Developer**, saya ingin mengaudit kode sumber proyek Android dan berkas `AndroidManifest.xml` sebelum dikompilasi menjadi APK, agar tidak ada komponen yang terekspos secara berbahaya saat rilis.                                       | 1. Perintah `/audit --apk` mendeteksi komponen dengan `android:exported="true"` tanpa izin dan konfigurasi `WebView` tidak aman.&#xA;2\. Agen menyediakan tambalan perbaikan langsung pada berkas XML maupun kode Kotlin/Java.                                                                                                |
| **US-04** | Sebagai **Tech Lead**, saya ingin menutup celah keamanan pada fungsi *library* pihak ketiga tanpa harus meng-*upgrade* versi paket yang berisiko merusak aplikasi utama.                                                                                  | 1. Perintah `/hotfix <nama-paket> --no-upgrade` memodifikasi fungsi rentan di dalam ruang isolasi.&#xA;2\. Sistem menghasilkan berkas `.patch` di folder `./patches/` dan membuktikan fungsi tersebut aman melalui *Security Unit Test* lokal.                                                                                |
| **US-05** | Sebagai **Security Architect**, saya ingin melihat pergerakan koloni Sub-Agent di kanvas TUI dan dapat mengintervensi (*pause/steer*) agen yang sedang berjalan maupun menambahkan `.skill.md` kustom perusahaan.                                         | 1. Pengguna dapat menggeser kanvas TUI dengan *mouse* pada 60 FPS tanpa *input lag*.&#xA;2\. Menekan `Space` pada *node* agen langsung menjeda eksekusi agen tersebut; menekan `s` menyuntikkan instruksi baru.&#xA;3\. Perintah `/skills import` dan `/skills synth` berhasil mendaftarkan *skill* baru ke *Skill Registry*. |
| **US-06** | Sebagai **Developer di Lingkungan Tertutup**, saya ingin menjalankan seluruh proses audit menggunakan model AI lokal di laptop saya tanpa koneksi internet, serta dapat membatalkan perubahan kode kapan saja.                                            | 1. Saat dikonfigurasi ke penyedia lokal (**Ollama**), 0 byte data dikirim ke internet publik.&#xA;2\. Menekan tombol `Esc` dua kali (`Esc+Esc`) mengembalikan kondisi berkas kode ke *checkpoint* awal secara utuh.                                                                                                           |

***

## 8. Metrik Keberhasilan Produk (*Success Metrics & KPIs*)

Untuk membuktikan dampak nyata karya ini di hadapan dewan juri maupun pengguna industri, keberhasilan produk diukur melalui 5 indikator kuantitatif berikut:

1. **Tingkat Pengurangan Alarm Palsu (*****False-Positive Noise Reduction Rate*****):**
   * **Target:** **$\ge 90\%$** peringatan tidak relevan (*unreachable CVE* & kode yang sudah tersanitasi di *middleware*) berhasil disaring secara otomatis oleh *GraphCore* dan *Triage Agent* sebelum ditampilkan sebagai masalah kritis kepada pengguna.
2. **Tingkat Keberhasilan Kompilasi & Verifikasi Tambalan (*****Verified Patch Pass Rate*****):**
   * **Target:** **100%** draf tambalan kode (*Auto-Hardening Diff*) yang direkomendasikan sebagai "Siap Terap (*Ready to Merge*)" wajib sudah lulus kompilasi, lulus *Security Unit Test* lokal, dan lulus gerbang deterministik *Safe Outputs*.
3. **Penghematan Konsumsi Token Konteks (*****Token Efficiency Ratio*****):**
   * **Target:** Pengurangan konsumsi token sebesar **$\ge 80\%$** per sesi audit dibandingkan metode pembacaan repositori mentah, dicapai melalui kombinasi *Local Code Context Graph* dan *Progressive Disclosure* pada `.skill.md`.
4. **Kecepatan Umpan Balik Pengembang (*****Developer Time-to-Feedback*****):**
   * **Target:** Waktu mulai dingin aplikasi TUI **$\le 50 \text{ ms}$**, dan waktu penyelesaian audit inkremental lokal (`--diff-scope=local`) **$\le 15 \text{ detik}$**.
5. **Kepatuhan Isolasi Keamanan (*****Zero Boundary Violation*****):**
   * **Target:** **0%** kebocoran akses berkas di luar direktori proyek aktif (*100% blocked path traversal*) pada pengujian penetrasi internal terhadap *Policy Gate*.

***

## 9. Risiko Produk & Strategi Mitigasi

| No    | Kategori Risiko                                                             | Deskripsi Risiko                                                                                                                                                                              | Dampak | Strategi Mitigasi Arsitektural pada Asterisk                                                                                                                                                                                                                                     |
| ----- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** | **Kegagalan Build pada Proyek Target**                                      | Analisis *Function-Level Reachability* penuh membutuhkan proyek yang dapat dipetakan dengan baik; bagaimana jika kode lokal *developer* sedang dalam kondisi setengah jadi / gagal kompilasi? | Tinggi | `GraphCore` menggunakan **`tree-sitter`****&#x20;(Error-Tolerant AST Parser)** yang tetap mampu membangun pohon sintaks dan melacak *Call Graph* meskipun terdapat kesalahan sintaks pada sebagian berkas kode, serta memiliki *fallback* otomatis ke analisis tingkat *import*. |
| **2** | **Keterbatasan Kapasitas Model Lokal Kecil**                                | Saat pengguna memakai model lokal berukuran kecil (misal 7B–8B parameter di Ollama), kemampuan nalar model mungkin kurang tajam jika diberi tugas terlalu besar sekaligus.                    | Sedang | Karena *Orchestrator* memecah masalah menjadi sub-tugas sempit untuk tiap *Sub-Agent* dan menyuapkan data matang dari `GraphCore` beserta panduan langkah-demi-langkah dari `.skill.md`, model lokal berukuran kecil pun dapat bekerja dengan presisi tinggi.                    |
| **3** | **Serangan&#x20;*****Indirect Prompt Injection*****&#x20;dari Kode Target** | *Source code* atau paket *open-source* berbahaya yang sedang diaudit sengaja menyisipkan instruksi jebakan di dalam komentar kode untuk membajak agen agar mengeksekusi perintah berbahaya.   | Kritis | Mengimplementasikan **Background Security Classifier** (memvalidasi rencana *tool call* tanpa membaca teks alasan agen yang berpotensi tercemar) ditambah penguncian direktori *fail-closed* pada **Pre-Execution Policy Gate**.                                                 |
| **4** | **Konflik Berkas Saat Penambalan Paralel**                                  | Beberapa *Sub-Agent* mencoba menyunting berkas *source code* yang sama di waktu bersamaan atau merusak pekerjaan yang belum disimpan oleh *developer*.                                        | Tinggi | Seluruh eksperimen pengujian unit dan penulisan kode tambalan dilakukan di dalam ruang isolasi **Git Worktree (****`.asterisk/worktrees/`****)** dan dilindungi oleh *snapshot checkpoint* yang dapat di-*rewind* kapan saja.                                                    |
