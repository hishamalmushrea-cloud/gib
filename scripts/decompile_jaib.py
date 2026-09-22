#!/usr/bin/env python3
"""
decompile_jaib.py — استخراج وتحليل ملف APK بدون الحاجة لجافا
يعتمد على androguard (Python). يُخرج تقريراً نصياً عن:
المانيفست، الأذونات، الشاشات (Activities)، الخدمات، المستقبلات،
سلاسل النصوص (الميزات)، سلاسل DEX (عناوين API ومفاتيح)، الشهادة، المكتبات.

الاستخدام:
    .venv/bin/python scripts/decompile_jaib.py <path-to.apk> [output_dir]
"""
import sys, os, re, zipfile, hashlib, datetime, logging

logging.disable(logging.CRITICAL)  # كتم سجلات androguard

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    from androguard.core.axml import AXMLPrinter, ARSCParser
except Exception as e:
    print("FATAL: androguard not available:", e)
    sys.exit(2)


def out_write(f, text):
    f.write(text)
    f.write("\n")


def main():
    if len(sys.argv) < 2:
        print("usage: decompile_jaib.py <apk> [outdir]")
        sys.exit(1)
    apk_path = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else "decompile"
    os.makedirs(outdir, exist_ok=True)
    report = os.path.join(outdir, "REPORT.txt")

    print(f"[1/7] فتح {apk_path} ...")
    if not os.path.exists(apk_path):
        print("file not found:", apk_path); sys.exit(1)

    with open(report, "w", encoding="utf-8") as f:
        out_write(f, "=" * 70)
        out_write(f, "تقرير تفكيك التطبيق — Jaib Digital Wallet (com.ahd.jaib)")
        out_write(f, "أُعد في: " + datetime.datetime.now().isoformat())
        out_write(f, "=" * 70)

        # ---------- 1) معلومات الملف ----------
        print("[2/7] معلومات الملف ...")
        st = os.stat(apk_path)
        out_write(f, f"\n## الملف\n- الحجم: {st.st_size/1048576:.2f} MB")
        out_write(f, f"- SHA-256: {hashlib.sha256(open(apk_path,'rb').read()).hexdigest()}")
        z = zipfile.ZipFile(apk_path)
        names = z.namelist()
        out_write(f, f"- عدد الإدخالات: {len(names)}")
        out_write(f, f"- ملفات DEX: {sorted(n for n in names if n.startswith('classes') and n.endswith('.dex'))}")
        libs = sorted({n.split('/')[1] for n in names if n.startswith('lib/')})
        out_write(f, f"- مكتبات lib/ للأبنية: {libs}")
        out_write(f, f"- يوجد assets: {'assets/' in names}")
        big = sorted(names, key=lambda n: z.getinfo(n).file_size, reverse=True)[:15]
        out_write(f, "- أكبر الملفات:")
        for n in big:
            out_write(f, f"    {z.getinfo(n).file_size:>10,}  {n}")

        # ---------- 2) المانيفست ----------
        print("[3/7] المانيفست ...")
        try:
            a = APK(apk_path)
            out_write(f, "\n## المانيفست (AndroidManifest.xml)")
            out_write(f, f"- الحزمة: {a.get_package()}")
            out_write(f, f"- الإصدار: {a.get_androidversion_name()} (code {a.get_androidversion_code()})")
            out_write(f, f"- minSdk: {a.get_min_sdk_version()} | targetSdk: {a.get_target_sdk_version()}")
            out_write(f, f"- النشاط الرئيسي: {a.get_main_activity()}")

            out_write(f, f"\n### الأذونات ({len(a.get_permissions())})")
            for p in sorted(a.get_permissions()):
                out_write(f, f"  - {p}")

            out_write(f, f"\n### الشاشات Activities ({len(a.get_activities())})")
            for act in sorted(a.get_activities()):
                out_write(f, f"  - {act}")

            out_write(f, f"\n### الخدمات Services ({len(a.get_services())})")
            for s in sorted(a.get_services()):
                out_write(f, f"  - {s}")

            out_write(f, f"\n### المستقبلات Receivers ({len(a.get_receivers())})")
            for r in sorted(a.get_receivers()):
                out_write(f, f"  - {r}")

            out_write(f, f"\n### المزودون Providers ({len(a.get_providers())})")
            for pv in sorted(a.get_providers()):
                out_write(f, f"  - {pv}")

            out_write(f, "\n### ميزات الجهاز المطلوبة (uses-feature)")
            try:
                axml_tree = AXMLPrinter(z.read("AndroidManifest.xml")).get_xml()
                found = False
                for el in axml_tree.getElementsByTagName("uses-feature"):
                    found = True
                    out_write(f, "  - " + (el.getAttribute("android:name") or el.getAttribute("android:glEsVersion") or "") + " (required=" + (el.getAttribute("android:required") or "?") + ")")
                if not found:
                    out_write(f, "  (لا يوجد)")
            except Exception as e:
                out_write(f, "  (فشل قراءة uses-feature: %s)" % e)

            # ---------- 3) الشهادة ----------
            print("[4/7] الشهادة ...")
            out_write(f, "\n## شهادة التوقيع")
            try:
                sig_name = a.get_signature_name()
                out_write(f, f"- اسم الملف: {sig_name}")
                cert = a.get_certificate(sig_name)
                der = cert.dump() if hasattr(cert, "dump") else bytes(cert)
                out_write(f, f"- SHA-256 (DER): {hashlib.sha256(der).hexdigest()}")
                out_write(f, f"- SHA-1 (DER): {hashlib.sha1(der).hexdigest()}")
                try:
                    out_write(f, f"- المُصدر: {cert.issuer.native}")
                    out_write(f, f"- المالك: {cert.subject.native}")
                    out_write(f, f"- الصلاحية: {cert.not_valid_before} → {cert.not_valid_after}")
                except Exception:
                    pass
            except Exception as e:
                out_write(f, "  (فشل تفاصيل الشهادة: %s)" % e)
        except Exception as e:
            out_write(f, "\n## المانيفست (فشل): %s" % e)

        # ---------- 4) موارد النصوص (الميزات بالعربي) ----------
        print("[5/7] موارد النصوص ...")
        try:
            if "resources.arsc" in names:
                arsc = ARSCParser(z.read("resources.arsc"))
                strs = set()
                try:
                    for pkg, locales in arsc.get_resolved_strings().items():
                        for loc, resmap in locales.items():
                            for rid, s in resmap.items():
                                if isinstance(s, str):
                                    strs.add(s)
                except Exception:
                    pass
                out_write(f, f"\n## سلاسل الموارد (resources.arsc) — {len(strs)} سلسلة")
                interesting = [s for s in strs if 2 < len(s) < 200]
                for s in sorted(interesting):
                    out_write(f, "  • " + s)
        except Exception as e:
            out_write(f, "\n## الموارد (فشل): %s" % e)

        # ---------- 5) سلاسل DEX ----------
        print("[6/7] سلاسل DEX ...")
        dex_files = [n for n in names if n.startswith("classes") and n.endswith(".dex")]
        all_strings = set()
        for df in dex_files:
            try:
                dvm = DEX(z.read(df))
                for s in dvm.get_strings():
                    all_strings.add(s)
            except Exception as e:
                out_write(f, f"\n## DEX {df} (فشل): {e}")
        # ملف مستقل بكل السلاسل للبحث اليدوي
        try:
            with open(os.path.join(outdir, "dex_strings.txt"), "w", encoding="utf-8") as sf:
                for s in sorted(all_strings):
                    sf.write(s.replace("\n", "\\n") + "\n")
        except Exception:
            pass
        out_write(f, f"\n## سلاسل DEX — {len(all_strings)} سلسلة (محفوظة كاملة في dex_strings.txt)")
        # عناوين API/شبكات
        urls = sorted({s for s in all_strings if re.search(r'https?://', s)})
        out_write(f, f"\n### عناوين URL ({len(urls)})")
        for u in urls[:300]:
            out_write(f, "  " + u)
        # مفاتيح Firebase / Google
        fkeys = sorted({s for s in all_strings if re.search(r'AIza[0-9A-Za-z_-]{30,}', s)})
        out_write(f, f"\n### مفاتيح Firebase/Google ({len(fkeys)})")
        for k in fkeys[:50]:
            out_write(f, "  " + k)
        # أسماء الحزم المشار إليها
        pkgs = sorted({s for s in all_strings if re.fullmatch(r'[a-z][a-z0-9_]*(\.[a-z0-9_]+)+', s) and 'android' not in s})
        out_write(f, f"\n### أسماء حزم/فئات بارزة ({len(pkgs)})")
        for p in pkgs[:250]:
            out_write(f, "  " + p)
        # كلمات مفتاحية مالية
        out_write(f, "\n### سلاسل عربية (ميزات محتملة)")
        ar = sorted({s for s in all_strings if re.search(r'[\u0600-\u06FF]{4,}', s)})
        for s in ar[:400]:
            out_write(f, "  • " + s[:160])

        # ---------- 6) بنية الفئات ----------
        print("[7/7] بنية الفئات ...")
        out_write(f, "\n## بنية الفئات (الملفات البرمجية)")
        classes = set()
        for df in dex_files:
            try:
                dvm = DEX(z.read(df))
                for c in dvm.get_classes():
                    classes.add(c.get_name())
            except Exception:
                pass
        out_write(f, f"### إجمالي الفئات: {len(classes)}")
        for c in sorted(classes)[:500]:
            out_write(f, "  " + c)

    print("اكتمل التقرير:", report)
    print("ملخص سريع:")
    with open(report, encoding="utf-8") as f:
        txt = f.read()
    print("  سطور:", txt.count("\n"), "| أذونات:", txt.count("\n- android.permission"),
          "| Activities:", txt.count("\n  - ") - txt.count("\n  - "), "| URLs:", len(re.findall(r'https?://', txt)))


if __name__ == "__main__":
    main()
