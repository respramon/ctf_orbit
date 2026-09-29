# Kontribusi

1. Buat branch dengan perubahan yang terfokus.
2. Tambahkan fixture kecil dan tes dengan hasil yang dapat diverifikasi.
3. Tetapkan batas ukuran/iterasi dan dokumentasikan format yang didukung.
4. Perbarui CLI help, `docs/USAGE.md`, dan tabel cakupan bila kemampuan berubah.
5. Jalankan unittest, lint, format check, dan build sebagaimana README.
6. Buat pull request dengan masalah, perubahan perilaku, hasil verifikasi,
   dan batas yang belum ditangani.

Analisis `analyze` harus tetap lokal, tanpa menjalankan binary, memanggil
shell, atau mengunjungi URL yang ditemukan di artefak. Tambahkan operasi
jaringan hanya sebagai command eksplisit dengan target dan batas permintaan.

