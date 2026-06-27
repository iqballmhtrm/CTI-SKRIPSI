RESEARCH PRINCIPLES DOCUMENT
Scientific Constitution of the Research
STATUS: LOCKED  |  R-00 through R-14

Tujuan Dokumen
Dokumen ini mendefinisikan prinsip-prinsip metodologis yang menjadi landasan seluruh penelitian. Setiap keputusan konseptual, desain artefak, implementasi teknis, maupun evaluasi ilmiah harus dapat ditelusuri dan konsisten terhadap prinsip-prinsip yang tercantum di dalam dokumen ini.
Dokumen ini bukan merupakan bagian dari Bab III maupun Bab IV, melainkan artefak penelitian yang berfungsi sebagai acuan internal untuk menjaga konsistensi ilmiah selama proses penelitian hingga sidang.

Bagian I — Research Philosophy
Prinsip-prinsip yang mengatur posisi penelitian terhadap masalah penelitian.

P-01	Urutan Fondasi Penelitian
"Problem Domain mendahului Research Problem. Research Problem diturunkan dari Research Gap."
Tidak ada keputusan penelitian yang boleh diambil sebelum fondasi ini dikunci.

P-02	Pemisahan Teori dan Kontribusi
"Literature provides the concepts. The research provides the conceptual model."
Teori yang ada di Bab II adalah milik orang lain. Model konseptual di Bab III adalah kontribusi penelitian.

P-03	Evidence vs Artifact
"Evidence is not the artifact. Evidence is the scientific justification that allows the researcher to claim a Research Question has been answered."
Dashboard bukan evidence. Kemampuan artefak memenuhi acceptance criteria adalah evidence.

P-04	Posisi CTI dalam Model
"CTI tidak diposisikan sebagai tahapan proses maupun keluaran transformasi, melainkan sebagai domain konseptual yang membingkai seluruh model."
CTI adalah lingkungan konseptual yang memberikan makna terhadap seluruh simpul model — bukan salah satu simpul itu sendiri.

P-05	Vendor-Neutrality Model Konseptual
"Sampai R-09, tidak ada satu pun keputusan yang bergantung pada software. Model konseptual ini vendor-neutral — jika ELK Stack diganti platform lain, model tetap valid."
Yang berubah saat platform diganti adalah implementasi, bukan capability dan bukan model konseptual.

P-06	Traceability sebagai Standar
"Setiap konsep tambahan yang ingin dimasukkan pada tahap berikutnya harus dapat dipetakan sebagai turunan atau pendukung dari salah satu dari lima konsep inti."
Konsep Backbone: Security Event → Contextualization → Actionable Intelligence → Operational Decision Support, dalam domain CTI.

Bagian II — Design Philosophy
Prinsip-prinsip yang mengatur bagaimana artefak dirancang.

P-07	Definisi Actionable
"Actionable bukan sifat informasi. Actionable adalah relasi antara informasi dan keputusan yang harus diambil."
Implikasi: mengevaluasi actionable bukan dengan bertanya apakah informasinya lengkap, tetapi apakah ia membantu memilih tindakan.

P-08	Operational Definition vs Universal Truth
"Ini adalah operational definition — bukan universal truth."
Actionable Intelligence Criteria berlaku dalam ruang lingkup penelitian ini. Penelitian tidak mengklaim universalitas.

P-09	Pemisahan Capability dan Fitur
"R-11 mendefinisikan kemampuan artefak — bukan fitur, bukan tools, bukan implementasi."
Capability menjawab 'apa yang harus mampu dilakukan'. Fitur menjawab 'apa yang tersedia'. Keduanya berbeda.

P-10	Design Pattern Capability
"Setiap capability dibangun dengan satu logika desain yang konsisten: Acquire → Process → Present → Explain."
Pola ini berlaku untuk seluruh 13 Artifact Capabilities (AC-1 sampai AC-13).

P-11	Traceability Keputusan Teknis
"Bukan: 'Saya memakai Filebeat.' Tetapi: 'Saya membutuhkan Structured Event Collection untuk memenuhi AC-1. Filebeat dipilih karena mampu mewujudkan mekanisme tersebut.'"
Setiap komponen teknis harus dapat ditelusuri ke capability yang diwujudkannya.

P-12	Evidence vs Explainability
"MITRE dan Threat Score adalah evidence — bukan penjelasan. Explainability adalah capability yang berbeda dari evidence."
AC-7 Priority Transparency membutuhkan mekanisme yang menjelaskan mengapa skor terbentuk, bukan sekadar menampilkan skornya.

Bagian III — Engineering Philosophy
Prinsip-prinsip yang mengatur proses implementasi.

P-13	Pusat Kontribusi Ilmiah
"Layer 3 adalah pusat risiko sekaligus pusat kontribusi penelitian — bukan karena paling sulit diprogram, tetapi karena di sinilah seluruh klaim ilmiah penelitian diuji secara nyata."
AC-8, AC-9, AC-10 adalah capability yang paling kritis dan paling mungkin menjadi fokus pertanyaan penguji.

P-14	Prinsip Validasi
"Validation menguji capability, bukan konfigurasi. Konfigurasi hanya menjadi evidence bahwa capability tersebut telah diwujudkan."
Pipeline berjalan bukan berarti capability terpenuhi. Acceptance criteria harus dibuktikan secara eksplisit.

Bagian IV — Evaluation Philosophy
Prinsip-prinsip yang mengatur evaluasi ilmiah penelitian.

P-15	Objek Evaluasi RQ-3
"RQ-3 tidak dievaluasi berdasarkan apakah keputusan menjadi lebih baik. RQ-3 dievaluasi berdasarkan apakah artefak berhasil menghasilkan keluaran yang memenuhi seluruh operational definition dari Actionable Intelligence."
Tidak ada survei pengguna, tidak ada usability study. Yang diukur adalah kualitas keluaran artefak terhadap NC-1 sampai NC-4.

P-16	Status Skenario Evaluasi
"Nmap, Hydra, dan Nikto bukan objek yang divalidasi. Mereka adalah instrumen evaluasi. Yang divalidasi tetap NC-1 sampai NC-4."
Ketiga skenario dipilih karena mewakili tiga kelas security event dengan karakteristik konteks, prioritas, dan implikasi keputusan yang berbeda.

Peta Traceability R-00 — R-14
Setiap fase penelitian terhubung dalam satu rantai yang tidak putus.

Fase	R-Code	Fungsi dalam Penelitian
Fondasi	R-00 – R-04	Mengapa penelitian diperlukan
Arah	R-05 – R-07	Apa yang ingin dicapai
Konsep	R-08 – R-09	Bagaimana struktur penelitiannya
Standar	R-10	Apa standar mutu keluarannya
Capability	R-11	Apa yang harus mampu dilakukan artefak
Spesifikasi	R-12	Apa yang diimplementasikan
Engineering	R-13	Bagaimana dibangun dan divalidasi
Evaluasi	R-14	Bagaimana dibuktikan secara ilmiah

Status Dokumen
Status	LOCKED — Tidak dapat diubah tanpa justifikasi metodologis
Fungsi	Acuan metodologis resmi selama proses penelitian, penulisan Bab III–IV, dan sidang
Berlaku untuk	Bab III, Bab IV, artikel ilmiah, dan seluruh keputusan engineering

Seluruh perubahan metodologi setelah dokumen ini dikunci harus dapat dipertanggungjawabkan secara ilmiah
dan ditelusuri terhadap prinsip-prinsip yang telah ditetapkan di sini.
