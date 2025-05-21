# CEKA Admin Panel Scanner Tool

![Python](https://img.shields.io/badge/Python-3.x-blue )
![License](https://img.shields.io/github/license/CEKA-Tools/admin-scanner )

**CEKA Admin Panel Scanner** هي أداة CLI (خط أوامر) مكتوبة بلغة Python تُستخدم لاكتشاف لوحات التحكم الإدارية (Admin Panels) باستخدام قائمة كلمات (Wordlist)، مع دعم البروكسي وشبكة Tor.

هذه الأداة مخصصة لأغراض اختبار الاختراق الأخلاقي فقط، ويجب استخدامها ضمن نطاق قانوني وأخلاقي.

---

## 🔧 الميزات

- ✅ كشف لوحات التحكم عبر Wordlist ضخمة.
- ✅ دعم البحث العشوائي (Random User-Agent).
- ✅ دعم الـ Proxy (HTTP/SOCKS).
- ✅ دعم شبكة Tor.
- ✅ واجهة خط الأوامر سهلة الاستخدام.
- ✅ حفظ النتائج في ملف نصي.
- ✅ إمكانية تعديل Wordlist بسهولة.
- ✅ واجهة ويب اختيارية (Flask).

---

## 📦 المتطلبات

تأكد من تثبيت المكتبات التالية:

- requests
- fake-useragent


أو يمكنك تثبيت جميع المتطلبات عبر ملف `requirements.txt`:

```bash
pip install -r requirements.txt --break-system-packages