#!/usr/bin/env python3
"""
decompile_jaib.py — استخراج وتحليل ملف APK بدون الحاجة لجافا
يعتمد على androguard (Python). يُخرج تقريراً نصياً عن:
المانيفست، الأذونات، الشاشات (Activities)، الخدمات، المستقبلات،
سلاسل النصوص (الميزات)، سلاسل DEX (عناوين API ومفاتيح)، الشهادة، المكتبات.

الاستخدام:
    .venv/bin/python scripts/decompile_jaib.py <path-to.apk> [output_dir]
"""
import sys, os, re, zipfile, hashlib, datetime

try:
    from androguard.core.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
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

            out_write(f, f"\n### الملفات المعرّفة (schemes/features)")
            for x in sorted(a.get_android_manifest_axml().get_xml().getElementsByTagName("uses-feature") or []):
                pass
            try:
                axml = a.get_android_manifest_axml()
                for el in axml.get_xml().getElementsByTagName("uses-feature"):
                    out_write(f, "  - feature: " + (el.getAttribute("android:name") or "") + " (required=" + (el.getAttribute("android:required") or "?") + ")")
                for el in axml.get_xml().getElementsByTagName("uses-sdk"):
                    out_write(f, "  - sdk: " + el.toxml()[:200])
            except Exception as e:
                out_write(f, "  (فشل قراءة تفاصيل المانيفست: %s)" % e)

            # ---------- 3) الشهادة ----------
            print("[4/7] الشهادة ...")
            try:
                out_write(f, "\n## شهادة التوقيع")
                out_write(f, f"- اسم الملف: {a.get_signature_name()}")
                cert = a.get_certificate()
                for h in (hashlib.sha256(cert), hashlib.sha1(cert)):
                    out_write(f, f"- {h.name}: {h.hexdigest()}")
            except Exception as e:
                out_write(f, "\n## الشهادة (فشل): %s" % e)
        except Exception as e:
            out_write(f, "\n## المانيفست (فشل): %s" % e)

        # ---------- 4) موارد النصوص (الميزات بالعربي) ----------
        print("[5/7] موارد النصوص ...")
        try:
            if "resources.arsc" in names:
                arsc = ARSCParser(z.read("resources.arsc"))
                strs = set()
                try:
                    for s in arsc.get_strings():
                        strs.add(s)
                except Exception:
                    pass
                out_write(f, f"\n## سلاسل الموارد (resources.arsc) — {len(strs)} سلسلة")
                interesting = [s for s in strs if isinstance(s, str) and 2 < len(s) < 200]
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
                dvm = DalvikVMFormat(z.read(df))
                for s in dvm.get_strings():
                    all_strings.add(s)
            except Exception as e:
                out_write(f, f"\n## DEX {df} (فشل): {e}")
        out_write(f, f"\n## سلاسل DEX — {len(all_strings)} سلسلة")
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
                dvm = DalvikVMFormat(z.read(df))
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
