# تحليل تطبيق جيب (Jaib Digital Wallet)

هذا المستودع يحتوي تحليلاً شاملاً لتطبيق **جيب — المحفظة الرقمية** (com.ahd.jaib) من شركة AHD FINANCIAL.

- 📄 **التقرير الكامل:** [ANALYSIS.md](ANALYSIS.md)
- 📥 **روابط التحميل الرسمية:** Google Play (com.ahd.jaib) • e-jaib.com/d.html • Huawei AppGallery (C109370979) • App Store (id6472856710)
- ⚙️ **سكربت جلب الـ APK من الموقع الرسمي:** `bash scripts/fetch_jaib.sh`
- 🔍 **سكربت فك التجميع (بدون جافا):** بعد وضع ملف الـ APK في المجلد، شغّل:
  ```
  .venv/bin/python scripts/decompile_jaib.py apk/jaib-digital-wallet.apk decompile/
  ```
  الناتج: تقرير كامل في `decompile/REPORT.txt` (أذونات، شاشات، خدمات، سلاسل، عناوين API، شهادة التوقيع).
