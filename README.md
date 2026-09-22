# 🌟 gib

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white) ![Repo Size](https://img.shields.io/github/repo-size/hishamalmushrea-cloud/gib?style=for-the-badge) ![Issues](https://img.shields.io/github/issues/hishamalmushrea-cloud/gib?style=for-the-badge) ![Last Commit](https://img.shields.io/github/last-commit/hishamalmushrea-cloud/gib?style=for-the-badge) [![License](https://img.shields.io/github/license/hishamalmushrea-cloud/gib?style=for-the-badge)](https://github.com/hishamalmushrea-cloud/gib/blob/main/LICENSE)

## 📖 About this Project
Welcome to the gib repository!

## 🚀 Tech Stack
- **Primary Language:** Python

## 🔗 Connect & Support
[![Trendshift](https://trendshift.io/api/badge/repositories/4119)](https://trendshift.io/)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289DA?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/)
[![X (formerly Twitter) Follow](https://img.shields.io/twitter/follow/hishamalmushrea-cloud?style=social)](https://x.com/hishamalmushrea-cloud)

---

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