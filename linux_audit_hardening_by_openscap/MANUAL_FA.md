# راهنمای عملیاتی ممیزی CIS با OpenSCAP

نسخه سند: 2026-09-20

این راهنما برای اجرای **audit فقط‌خواندنی** روی سرورهای عملیاتی Ubuntu و Debian نوشته شده است. در هیچ دستور audit گزینه `--remediate` استفاده نمی‌شود. نصب scanner و قراردادن محتوای SCAP تغییر نرم‌افزاری محسوب می‌شود و بهتر است پیش از پنجره ممیزی انجام شود.

## پاسخ کوتاه درباره Levelها

- **CIS Level 1** خط پایه کم‌اختلال‌تر و مناسب‌تر برای اغلب سرورهاست.
- **CIS Level 2** سخت‌گیرانه‌تر است، کنترل‌های بیشتری دارد و احتمال اثر روی سرویس بیشتر است.
- گزارش قبلی Rocky Linux با **Level 1 Server** گرفته شد، نه Level 2.

## ماتریس بررسی‌شده نام فایل و پروفایل

| سیستم‌عامل | DataStream | CIS Level 1 Server | CIS Level 2 Server | محتوای پیشنهادی |
|---|---|---|---|---|
| Ubuntu 20.04 | `ssg-ubuntu2004-ds.xml` | `xccdf_org.ssgproject.content_profile_cis_level1_server` | `xccdf_org.ssgproject.content_profile_cis_level2_server` | ComplianceAsCode 0.1.71 |
| Ubuntu 22.04 | `ssg-ubuntu2204-ds.xml` | همان ID بالا | همان ID بالا | ComplianceAsCode 0.1.82 |
| Ubuntu 24.04 | `ssg-ubuntu2404-ds.xml` | همان ID بالا | همان ID بالا | ComplianceAsCode 0.1.82 |
| Debian 11 | `ssg-debian11-ds.xml` | **وجود ندارد** | **وجود ندارد** | فقط Standard/ANSSI؛ CIS نامیده نشود |
| Debian 12 | `ssg-debian12-ds.xml` | همان ID بالا | همان ID بالا | ComplianceAsCode 0.1.82 |
| Debian 13 | `ssg-debian13-ds.xml` | همان ID بالا | همان ID بالا | ComplianceAsCode 0.1.82 |

این ماتریس از DataStreamهای pre-built رسمی v0.1.82 استخراج شده است. v0.1.82 دیگر فایل Ubuntu 20.04 ندارد؛ برای Ubuntu 20.04 از محتوای 0.1.71 استفاده شده که فایل و پروفایل‌های فوق را دارد. Debian 11 در v0.1.82 پروفایل CIS ندارد؛ اجرای profile استاندارد Debian 11 یک audit عمومی است و **گواه CIS نیست**.

## معماری کنترل منابع

اسکریپت همراه، OpenSCAP را داخل transient systemd service اجرا می‌کند:

- `CPUQuota=200%`: حداکثر معادل دو هسته CPU. این quota است و پردازش را به شماره هسته خاص pin نمی‌کند.
- `MemoryHigh=3584M`: از 3.5 GiB به بعد فشار reclaim ایجاد می‌شود.
- `MemoryMax=4G`: سقف سخت RAM گروه پردازش.
- `MemorySwapMax=0`: مصرف swap توسط scan مجاز نیست.
- `Nice=10` و `IOSchedulingClass=idle`: اولویت CPU و I/O پایین‌تر از workload عادی.
- `RuntimeMaxSec=2h`: توقف در صورت طولانی‌شدن بیش از دو ساعت.
- اگر مصرف کل میزبان CPU یا RAM در سه نمونه متوالی به 80٪ برسد، scan متوقف می‌شود.
- اگر filesystem خروجی به 90٪ برسد یا فضای آزاد آن کمتر از 1 GiB شود، scan متوقف می‌شود.
- پیش از شروع حداقل 5 GiB فضای آزاد، کمتر از 85٪ مصرف filesystem و کمتر از 90٪ مصرف inode لازم است.

توقف بر اساس مصرف **کل میزبان** ممکن است به‌دلیل بار یک سرویس دیگر رخ دهد؛ این رفتار محافظه‌کارانه و عمدی است. خروجی scan متوقف‌شده معتبر نیست و با فایل `ABORTED-HOST-RESOURCE` علامت‌گذاری می‌شود.

## 1) پیش‌نیاز و شناسایی سرور

با حساب sudo‌دار یا root وارد شوید. رمز را در command line یا history قرار ندهید.

```bash
sudo -i
cat /etc/os-release
uname -r
nproc
free -h
df -hT /
df -ih /
systemd --version | head -n 1
```

اگر سرور container است، systemd ندارد، کمتر از دو CPU دارد، filesystem نزدیک ظرفیت است یا maintenance policy اجرای scanner را منع می‌کند، ادامه ندهید و روش را با تیم عملیات تطبیق دهید.

## 2) نصب scanner و ابزارهای لازم

Ubuntu 20.04/22.04/24.04 و Debian 11/12/13:

```bash
sudo -i
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends openscap-scanner ca-certificates curl unzip procps
unset DEBIAN_FRONTEND

command -v oscap
oscap --version
systemd-run --version
```

نصب بسته را پیش از پنجره audit انجام دهید. ارتقای کلی سیستم (`apt-get upgrade`) بخشی از این procedure نیست.

## 3) نصب محتوای رسمی ComplianceAsCode با کنترل SHA-512

### Ubuntu 22.04/24.04 و Debian 11/12/13

```bash
sudo -i
SSG_VERSION=0.1.82
STAGE_DIR=/var/tmp/ssg-stage-${SSG_VERSION}
install -d -m 0700 "$STAGE_DIR" /opt/complianceascode
cd "$STAGE_DIR"

curl -fL --retry 3 --proto '=https' --tlsv1.2 \
  -O "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip"
curl -fL --retry 3 --proto '=https' --tlsv1.2 \
  -O "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip.sha512"

sha512sum -c "scap-security-guide-${SSG_VERSION}.zip.sha512"
unzip -q "scap-security-guide-${SSG_VERSION}.zip" -d /opt/complianceascode
chown -R root:root "/opt/complianceascode/scap-security-guide-${SSG_VERSION}"
chmod -R go-w "/opt/complianceascode/scap-security-guide-${SSG_VERSION}"
```

خروجی `sha512sum` باید `OK` باشد. در غیر این صورت فایل را استفاده نکنید.

SHA-512 رسمی v0.1.82 که هنگام تدوین این سند مستقل بررسی شد:

```text
1caea418f0a5aaef7025e1655ca45a80942ea87ee832b943644ba6f9991b14a6ac5b35dddcd04b754e1fc8fbdee7b7f394507d24b123e821cca0354dc4e03cfd
```

### Ubuntu 20.04

Ubuntu 20.04 در release جدید v0.1.82 وجود ندارد. محتوای 0.1.71 را نصب و checksum رسمی همراه همان release را بررسی کنید:

```bash
sudo -i
SSG_VERSION=0.1.71
STAGE_DIR=/var/tmp/ssg-stage-${SSG_VERSION}
install -d -m 0700 "$STAGE_DIR" /opt/complianceascode
cd "$STAGE_DIR"

curl -fL --retry 3 --proto '=https' --tlsv1.2 \
  -O "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip"
curl -fL --retry 3 --proto '=https' --tlsv1.2 \
  -O "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VERSION}/scap-security-guide-${SSG_VERSION}.zip.sha512"

sha512sum -c "scap-security-guide-${SSG_VERSION}.zip.sha512"
unzip -q "scap-security-guide-${SSG_VERSION}.zip" -d /opt/complianceascode
chown -R root:root "/opt/complianceascode/scap-security-guide-${SSG_VERSION}"
chmod -R go-w "/opt/complianceascode/scap-security-guide-${SSG_VERSION}"
```

Ubuntu 20.04 از دوره پشتیبانی استاندارد خارج شده است؛ وضعیت Ubuntu Pro/ESM و برنامه ارتقا باید جداگانه بررسی شود. استفاده از benchmark قدیمی‌تر را در گزارش ریسک ثبت کنید.

### نصب آفلاین

روی workstation متصل، هر دو فایل ZIP و `.sha512` را از URLهای بالا بگیرید، سپس:

```bash
scp scap-security-guide-0.1.82.zip scap-security-guide-0.1.82.zip.sha512 admin@SERVER_IP:/var/tmp/
```

روی سرور:

```bash
sudo -i
cd /var/tmp
sha512sum -c scap-security-guide-0.1.82.zip.sha512
install -d -m 0755 /opt/complianceascode
unzip -q scap-security-guide-0.1.82.zip -d /opt/complianceascode
chown -R root:root /opt/complianceascode/scap-security-guide-0.1.82
chmod -R go-w /opt/complianceascode/scap-security-guide-0.1.82
```

برای Ubuntu 20.04 عدد نسخه را در سه محل بالا با `0.1.71` جایگزین کنید.

## 4) اعتبارسنجی نام فایل و profile روی خود سرور

هیچ‌گاه فقط به جدول سند اکتفا نکنید؛ وجود فایل و profile را روی همان سرور fail-closed کنترل کنید.

نمونه Ubuntu 24.04:

```bash
DS=/opt/complianceascode/scap-security-guide-0.1.82/ssg-ubuntu2404-ds.xml
PROFILE=xccdf_org.ssgproject.content_profile_cis_level1_server

test -r "$DS"
oscap info "$DS" | tee /var/tmp/oscap-info.txt
grep -F "Id: $PROFILE" /var/tmp/oscap-info.txt
```

اعتبارسنجی DataStream با محدودیت یک CPU، یک GiB RAM و 10 دقیقه زمان:

```bash
systemd-run --wait --pipe --collect \
  --unit="openscap-validate-$(date +%s)" \
  --property=Type=exec \
  --property=CPUQuota=100% \
  --property=MemoryMax=1G \
  --property=RuntimeMaxSec=10min \
  --property=Nice=10 \
  --property=IOSchedulingClass=idle \
  /usr/bin/oscap ds sds-validate "$DS"
```

اگر validation یا grep profile موفق نبود، audit را اجرا نکنید.

## 5) نصب runner محافظت‌شده

فایل همراه `cis-openscap-audit.sh` را با SCP به `/var/tmp` منتقل کنید:

```bash
scp cis-openscap-audit.sh admin@SERVER_IP:/var/tmp/
```

سپس روی سرور:

```bash
sudo -i
install -o root -g root -m 0750 /var/tmp/cis-openscap-audit.sh /usr/local/sbin/cis-openscap-audit
bash -n /usr/local/sbin/cis-openscap-audit
sha256sum /usr/local/sbin/cis-openscap-audit
```

## 6) اجرای CIS Level 1 Server

این انتخاب پیش‌فرض و پیشنهاد عملیاتی است:

```bash
sudo -i
PROFILE_LEVEL=1 /usr/local/sbin/cis-openscap-audit
```

اسکریپت OS را تشخیص می‌دهد، فایل صحیح را انتخاب می‌کند، precheckها را انجام می‌دهد و مسیر خروجی نهایی را چاپ می‌کند.

## 7) اجرای CIS Level 2 Server

فقط پس از تأیید امنیت و مالک سرویس:

```bash
sudo -i
PROFILE_LEVEL=2 /usr/local/sbin/cis-openscap-audit
```

## 8) Debian 11

ComplianceAsCode v0.1.82 برای Debian 11 پروفایل CIS ندارد. runner اجرای CIS را عمداً رد می‌کند. اگر سازمان صراحتاً baseline غیر-CIS را پذیرفته است:

```bash
sudo -i
PROFILE_LEVEL=standard /usr/local/sbin/cis-openscap-audit
```

روی گزارش و ticket بنویسید: **Standard System Security Profile for Debian 11 — NOT CIS**. برای ارزیابی رسمی CIS Debian 11 باید از محتوای مجاز و معتبر CIS یا ابزار CIS-CAT متناسب با مجوز سازمان استفاده شود.

## 9) تغییر محدودیت‌ها در صورت تصویب عملیات

پیش‌فرض‌ها را فقط برای همان command تغییر دهید؛ فایل script را ویرایش نکنید:

```bash
CPU_QUOTA=100% \
MEMORY_HIGH=1792M \
MEMORY_MAX=2G \
RUNTIME_MAX=90min \
HOST_CPU_KILL_PCT=75 \
HOST_MEM_KILL_PCT=75 \
PROFILE_LEVEL=1 \
/usr/local/sbin/cis-openscap-audit
```

`CPUQuota=100%` یعنی ظرفیت یک هسته؛ `200%` یعنی دو هسته. سقف کمتر ممکن است زمان اسکن filesystem را بسیار طولانی کند.

## 10) مشاهده وضعیت بدون دستکاری scan

از SSH session دوم:

```bash
systemctl list-units 'openscap-cis-*'
systemd-cgtop --depth=3
ps -eo pid,etime,pcpu,pmem,ni,stat,cmd | grep '[o]scap'
df -h /var/lib/openscap-audit
df -ih /var/lib/openscap-audit
journalctl -f -u 'openscap-cis-*'
```

برای توقف دستی:

```bash
UNIT=$(systemctl list-units --type=service --all --plain --no-legend 'openscap-cis-*' | awk 'NR==1 {print $1}')
test -n "$UNIT" && systemctl stop "$UNIT"
```

خروجی توقف‌داده‌شده را نتیجه معتبر تلقی نکنید.

## 11) بررسی و تحویل خروجی

مسیر خروجی شبیه زیر است:

```text
/var/lib/openscap-audit/HOST-ubuntu2404-cis_level1_server-YYYYMMDDTHHMMSSZ/
```

فایل‌های معتبر:

- `report.html`: گزارش خوانا.
- `results-arf.xml`: نتیجه کامل ماشین‌خوان.
- `manifest.txt`: OS، profile، hash محتوا و limitها.
- `journal.log`: log اجرای transient service.
- `oscap-exit-code`: کد خروجی scanner.
- `SHA256SUMS`: کنترل تمامیت فایل‌ها.

روی سرور:

```bash
OUT_DIR=$(find /var/lib/openscap-audit -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | awk 'NR==1 {$1=""; sub(/^ /,""); print}')
test -n "$OUT_DIR"
test ! -e "$OUT_DIR/ABORTED-HOST-RESOURCE"
cd "$OUT_DIR"
sha256sum -c SHA256SUMS
cat oscap-exit-code
ls -lh
```

معنی کدهای مهم:

- `0`: evaluation اجرا شده و نتیجه را در گزارش ببینید.
- `2`: evaluation کامل شده و حداقل یک rule پاس نشده؛ شکست scanner نیست.
- سایر کدها یا نبود `oscap-exit-code`: خطای فنی یا توقف؛ گزارش را معتبر ندانید.

انتقال از workstation:

```bash
scp -r admin@SERVER_IP:/var/lib/openscap-audit/HOST-PRODUCT-PROFILE-TIMESTAMP ./
cd HOST-PRODUCT-PROFILE-TIMESTAMP
sha256sum -c SHA256SUMS
```

گزارش شامل اطلاعات حساس میزبان است؛ آن را در مسیر کنترل‌شده، با encryption at rest و retention مصوب نگهداری کنید.

## 12) نکات ضروری محیط عملیاتی

1. scan را در ساعت کم‌بار و ترجیحاً maintenance window اجرا کنید.
2. پیش از شروع، backup/restore، مانیتورینگ سرویس و دسترسی کنسول out-of-band را بررسی کنید.
3. هم‌زمان backup سنگین، antivirus full scan، indexing یا OpenSCAP دیگری اجرا نکنید.
4. روی NFS/CIFS یا filesystem کند خروجی ننویسید؛ از storage محلی کنترل‌شده استفاده کنید.
5. `--oval-results` می‌تواند ARF بزرگی تولید کند؛ حداقل 5 GiB رزرو این راهنما محافظه‌کارانه است.
6. scan مالکیت و permission کل filesystem روی file server، database و Splunk ممکن است طولانی باشد.
7. pass/fail را با scope و applicability بررسی کنید؛ `notapplicable` را pass حساب نکنید.
8. تفاوت نسخه benchmark، نسخه SSG و نسخه OS را در ticket ثبت کنید.
9. audit را با remediation اشتباه نگیرید. script اصلاحی را مستقیم روی production اجرا نکنید.
10. تغییرات PAM، SSH، firewall، bootloader و filesystem mount باید جداگانه review، test و rollback داشته باشند.
11. پس از هر remediation، health check سرویس و audit مجدد لازم است.
12. Ubuntu 20.04 و Debian 11 را به‌دلیل عمر و پوشش محتوای قدیمی در برنامه ارتقا قرار دهید.

## 13) پاک‌سازی staging پس از تأیید تحویل

پاک‌سازی اختیاری است و فقط پس از تأیید انتقال گزارش انجام شود:

```bash
sudo -i
find /var/tmp -maxdepth 1 -type d -name 'ssg-stage-*' -print
```

مسیر چاپ‌شده را بررسی کنید و سپس فقط همان staging directory مشخص را حذف کنید. DataStream زیر `/opt/complianceascode` و نتایج زیر `/var/lib/openscap-audit` را تا پایان retention حذف نکنید.

## دامنه بررسی و تست این سند

- آرشیو pre-built رسمی `scap-security-guide-0.1.82.zip` دانلود شد و SHA-512 آن با فایل checksum رسمی تطابق کامل داشت.
- وجود پنج DataStream مربوط به Ubuntu 22.04/24.04 و Debian 11/12/13 مستقیماً داخل ZIP کنترل شد.
- Profile ID و عنوان تمام profileهای هر DataStream از XML استخراج شد؛ CIS Level 1/2 Server برای Ubuntu 22/24 و Debian 12/13 تأیید شد و نبود CIS در Debian 11 نیز تأیید شد.
- وجود فایل و profileهای Ubuntu 20.04 در بسته رسمی `ssg-debderived 0.1.71` کنترل شد؛ این محصول در release جدید 0.1.82 حذف شده است.
- syntax فایل `cis-openscap-audit.sh` با `bash -n` روی Linux واقعی بررسی و موفق شد.
- اجرای end-to-end OpenSCAP با خروجی HTML/ARF و کد 2 روی Rocky Linux 8.10 انجام شده است.
- میزبان زنده Ubuntu/Debian در دسترس این بررسی نبود؛ بنابراین پیش از rollout سراسری، اجرای pilot روی یک clone یا سرور non-critical از هر OS/version الزامی است. هیچ سندی نمی‌تواند تفاوت filesystem، workload و packageهای هر پروژه را بدون pilot حذف کند.

منابع مرجع:

- `https://github.com/ComplianceAsCode/content/releases/tag/v0.1.82`
- `https://github.com/ComplianceAsCode/content/releases/download/v0.1.82/scap-security-guide-0.1.82.zip`
- `https://github.com/ComplianceAsCode/content/releases/download/v0.1.82/scap-security-guide-0.1.82.zip.sha512`
- `https://github.com/ComplianceAsCode/content`
- `https://packages.ubuntu.com/noble/ssg-debderived`
- `https://packages.debian.org/bookworm/ssg-debian`
- `https://packages.debian.org/trixie/ssg-debian`

## چک‌لیست تحویل کارشناس

```text
[ ] OS/Version و نقش سرور ثبت شد
[ ] Level 1 یا Level 2 با مالک سرویس تصویب شد
[ ] scanner از مخزن OS نصب شد
[ ] release رسمی SSG و فایل SHA-512 آن دریافت و OK شد
[ ] DataStream و Profile ID روی همان سرور کنترل شد
[ ] DataStream validation موفق بود
[ ] CPU/RAM/Runtime/Storage guard فعال بود
[ ] قبل از شروع CPU/RAM/space/inode در محدوده بود
[ ] scan بدون --remediate اجرا شد
[ ] ABORTED-HOST-RESOURCE وجود ندارد
[ ] exit code فقط 0 یا 2 است
[ ] HTML + ARF + manifest + journal + SHA256SUMS تحویل شد
[ ] checksum پس از انتقال OK شد
[ ] گزارش با نسخه benchmark و استثناهای scope ثبت شد
```
