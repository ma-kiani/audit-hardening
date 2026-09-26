# اجرای امن OpenSCAP CIS Audit روی Ubuntu 24.04 عملیاتی

این procedure فقط audit انجام می‌دهد و هیچ `--remediate`، Ansible remediation یا تغییر hardening اجرا نمی‌کند.

تنظیمات پیش‌فرض runner:

- پروفایل: CIS Ubuntu 24.04 Level 1 Server
- سقف CPU اسکن: `CPUQuota=200%`، معادل حداکثر ظرفیت دو هسته
- فشار نرم حافظه: `MemoryHigh=3584M`
- سقف سخت حافظه: `MemoryMax=4G`
- swap اسکن: صفر
- زمان حداکثر: دو ساعت
- توقف کامل cgroup اگر CPU کل میزبان، RAM کل میزبان یا filesystem خروجی به `90%` برسد
- فاصلهٔ پایش: پنج ثانیه

## ۱. پیش‌بررسی سرور عملیاتی

```bash
sudo -i
cat /etc/os-release
dpkg --print-architecture
ps -p 1 -o comm=
systemctl is-system-running
nproc
free -h
df -hT /
df -ih /
```

این نسخه برای Ubuntu 24.04، معماری amd64 و systemd نوشته شده است. بهتر است audit در بازهٔ کم‌بار اجرا شود.

## ۲. نصب OpenSCAP scanner

```bash
sudo -i
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends openscap-scanner ca-certificates curl python3
unset DEBIAN_FRONTEND
oscap --version
```

`apt-get upgrade` بخشی از این procedure نیست.

## ۳. دریافت محتوای رسمی Ubuntu 24.04

```bash
sudo -i
install -d -m 0700 /var/tmp/ssg-stage-0.1.82
install -d -m 0755 /opt/complianceascode
cd /var/tmp/ssg-stage-0.1.82

curl -fL --retry 3 --proto '=https' --tlsv1.2 \
  -O https://github.com/ComplianceAsCode/content/releases/download/v0.1.82/scap-security-guide-0.1.82.zip
curl -fL --retry 3 --proto '=https' --tlsv1.2 \
  -O https://github.com/ComplianceAsCode/content/releases/download/v0.1.82/scap-security-guide-0.1.82.zip.sha512

sha512sum -c scap-security-guide-0.1.82.zip.sha512
python3 -m zipfile -e scap-security-guide-0.1.82.zip /opt/complianceascode
chown -R root:root /opt/complianceascode/scap-security-guide-0.1.82
chmod -R go-w /opt/complianceascode/scap-security-guide-0.1.82
```

خروجی `sha512sum` باید `OK` باشد. در غیر این صورت ادامه ندهید.

## ۴. اعتبارسنجی DataStream و پروفایل

```bash
sudo -i
DS=/opt/complianceascode/scap-security-guide-0.1.82/ssg-ubuntu2404-ds.xml
PROFILE=xccdf_org.ssgproject.content_profile_cis_level1_server

test -r "$DS"
oscap info "$DS" | tee /var/tmp/oscap-info-ubuntu2404.txt
grep -F "Id: $PROFILE" /var/tmp/oscap-info-ubuntu2404.txt

systemd-run --wait --pipe \
  --unit="openscap-validate-$(date +%s)" \
  --property=Type=exec \
  --property=CPUQuota=100% \
  --property=MemoryMax=1G \
  --property=RuntimeMaxSec=10min \
  --property=Nice=10 \
  --property=IOSchedulingClass=idle \
  /usr/bin/oscap ds sds-validate "$DS"
```

اگر validation یا `grep` موفق نبود، audit را اجرا نکنید.

## ۵. نصب runner محافظت‌شده

از سیستمی که فایل `cis-openscap-audit.sh` روی آن قرار دارد:

```bash
scp cis-openscap-audit.sh admin@SERVER_IP:/var/tmp/
```

روی سرور عملیاتی:

```bash
sudo -i
install -o root -g root -m 0750 \
  /var/tmp/cis-openscap-audit.sh \
  /usr/local/sbin/cis-openscap-audit
bash -n /usr/local/sbin/cis-openscap-audit
sha256sum /usr/local/sbin/cis-openscap-audit
```

## ۶. اجرای audit با محدودیت‌های صریح

```bash
sudo -i
CPU_QUOTA=200% \
MEMORY_HIGH=3584M \
MEMORY_MAX=4G \
RUNTIME_MAX=2h \
HOST_CPU_KILL_PCT=90 \
HOST_MEM_KILL_PCT=90 \
FILESYSTEM_KILL_PCT=90 \
SAMPLE_INTERVAL=5 \
/usr/local/sbin/cis-openscap-audit
```

`CPUQuota=200%` مصرف CPU را به معادل دو هسته محدود می‌کند، ولی process را به شمارهٔ هسته‌های خاص pin نمی‌کند. watchdog مصرف کل میزبان را از `/proc/stat` و `/proc/meminfo` می‌خواند. رسیدن هرکدام از CPU یا RAM کل به ۹۰٪، یا رسیدن filesystem خروجی به ۹۰٪، کل service cgroup را متوقف می‌کند.

## ۷. مشاهده از SSH session دوم

```bash
systemctl list-units --type=service 'openscap-cis-*'
systemd-cgtop --depth=3
ps -eo pid,etime,pcpu,pmem,ni,stat,cmd | grep '[o]scap'
tail -f /var/lib/openscap-audit/*/resource-usage.csv
df -h /var/lib/openscap-audit
```

## ۸. بررسی خروجی

```bash
OUT_DIR="$(find /var/lib/openscap-audit -mindepth 1 -maxdepth 1 \
  -type d -printf '%T@ %p\n' | sort -nr | awk 'NR==1 {$1=""; sub(/^ /,""); print}')"

test -n "$OUT_DIR"
test ! -e "$OUT_DIR/ABORTED-HOST-RESOURCE"
cd "$OUT_DIR"
sha256sum -c SHA256SUMS
cat oscap-exit-code
cat resource-usage.csv
ls -lh
```

فایل‌های اصلی:

- `report.html`: گزارش قابل‌خواندن
- `results-arf.xml`: نتیجهٔ ماشین‌خوان
- `resource-usage.csv`: مصرف CPU/RAM/filesystem کل میزبان در زمان اجرا
- `manifest.txt`: پروفایل، hash محتوا و محدودیت‌های اجرا
- `journal.log`: log سرویس
- `oscap-exit-code`: کد خروجی scanner
- `SHA256SUMS`: کنترل تمامیت فایل‌ها

معنی کدها:

- `0`: evaluation کامل شد و rule ناموفق وجود ندارد.
- `2`: evaluation کامل شد و حداقل یک rule ناموفق است؛ این خطای scanner نیست.
- `9` همراه `ABORTED-HOST-RESOURCE`: watchdog اسکن را متوقف کرده و گزارش کامل/معتبر نیست.
- کد دیگر یا نبود فایل خروجی: خطای فنی؛ `journal.log` را بررسی کنید.

## ۹. انتقال امن گزارش

روی workstation:

```bash
scp -r admin@SERVER_IP:/var/lib/openscap-audit/HOST-ubuntu2404-cis-level1-server-TIMESTAMP ./
cd HOST-ubuntu2404-cis-level1-server-TIMESTAMP
sha256sum -c SHA256SUMS
```

گزارش ARF و HTML می‌تواند شامل نام میزبان، packageها، userها و تنظیمات امنیتی باشد؛ آن را در storage کنترل‌شده نگه دارید.

## نتیجهٔ اجرای مرجع

اجرای مرجع روی Ubuntu 24.04.5 با ComplianceAsCode 0.1.82:

- `132 pass`
- `18 fail`
- `258 notapplicable`
- `240 notselected`
- بیشینهٔ CPU کل مشاهده‌شده: ۱۳٪
- بیشینهٔ RAM کل مشاهده‌شده: ۱۰٪
- خروجی حدود ۲۰MiB
- exit code برابر ۲؛ evaluation کامل و دارای موارد عدم انطباق
- watchdog با آستانهٔ آزمایشی ۱٪ جداگانه تست شد؛ کل cgroup متوقف و هیچ process از `oscap` باقی نماند.

