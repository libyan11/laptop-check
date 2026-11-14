# Laptop Check

A portable, read-only inspection tool for **used Windows laptops and PCs**. Put it on a USB stick, double-click, and get a colour-coded report in about 10 minutes, covering everything from company locks and battery health to hidden malware and swapped parts.

It has three modes, one launcher each:

| Launcher | Use it when | What you get |
|---|---|---|
| `Run-LaptopCheck.bat` | **Buying**: at the seller's, before you pay | Deal-breaker checks, specs compared with the advert, malware scan |
| `Run-MyLaptopCheck.bat` | **Owning**: a laptop you have just bought | Deeper tests (full malware scan, longer stress test, battery run-time, Windows Update check) and an after-purchase to-do list |
| `Run-SellCheck.bat` | **Selling**: e.g. on eBay, before you wipe it | A ready-to-paste listing (title, specs, passed tests, known issues) and a privacy checklist for selling |

## Quick start

1. Download the `LaptopCheck` folder (or a release zip). If you downloaded a zip, right-click it, choose **Properties**, tick **Unblock**, then extract it.
2. Copy the `LaptopCheck` folder onto a USB stick.
3. On the laptop, double-click the launcher you need and click **Yes** on the administrator prompt.
4. The report opens by itself. It is saved in `LaptopCheck\Reports\<date>_<mode>_<brand>_<model>_<serial>\`.
5. Click **Open hands-on tests** for the screen, keyboard, touchpad, speakers, microphone and webcam tests, plus a physical inspection checklist.

No installation is needed. It runs on the Windows PowerShell 5.1 that comes with every copy of Windows 10 and 11.

## What it checks

- **Company lock:** Entra ID / Azure AD or domain join, Intune / MDM enrolment, **Autopilot registration**, SCCM and 20+ RMM / management agents, Defender for Endpoint, Absolute / Computrace anti-theft, **BIOS passwords** (read from firmware on Dell, HP and Lenovo), asset and ownership tags, company accounts, Wi-Fi and certificates, PowerShell lockdown.
- **Licence:** activation, a licence key built into the firmware, KMS / volume / pirated activation, edition, S mode, Windows 11 readiness.
- **Hardware:** battery health % and cycles, a charger / charging-port test, battery run-time, drive health / wear / errors / hours, RAM / CPU / GPU / storage compared with the advert, a quick RAM pattern test, a CPU full-load throttling test, disk speed, screen panel, Wi-Fi, Bluetooth, webcam, mic, keyboard, touchpad, touchscreen, fingerprint reader, ports, TPM, Secure Boot, and Device Manager errors and *disabled* devices.
- **Original parts:** mismatched or upgraded RAM, an aftermarket battery, a retail or no-name replacement drive, a replaced motherboard, and links to the maker's original-parts list for that serial number.
- **History:** blue screens, unexpected shutdowns, hardware (WHEA) errors, disk errors, CPU throttling events, cleared event logs, Defender switched off, suspicious PowerShell.
- **Security and malware:** Defender status, exclusions and detections; remote-control tools, spyware / keyloggers, crypto miners, cracks / activators and adware; start-up entries, scheduled tasks, services, drivers, WMI persistence, Winlogon / IFEO / login-screen backdoors, all with digital-signature checks; hosts file, proxy, DNS, interception certificates and open ports; a name / location scan of **every file** on every internal drive; Microsoft Defender quick or full scan; optional Sysinternals Autoruns / Sigcheck with VirusTotal hash lookups.
- **Brand-aware:** the brand and model are detected automatically, so the report shows the right BIOS key, built-in diagnostics, warranty lookup and lock checks for Dell, Lenovo, HP, ASUS, Acer, MSI, Microsoft Surface, Razer, Samsung and more.

Each run is added to `Reports\history.csv`, so the next report shows how battery health and drive wear have changed.

## Safety and privacy

- The tool **only reads**. It does not uninstall, delete or change settings. The only things it writes are its own report folder, plus Windows' own battery report, disk benchmark and (optional) Defender scan logs.
- Nothing is uploaded, except:
  - a 25 MB internet speed test (Cloudflare);
  - optional VirusTotal *hash* lookups if you add the Sysinternals tools. Files themselves are never uploaded.
- Reports contain details about the PC they ran on. They are excluded from git by `.gitignore`.

## Limits

Software cannot see physical or liquid damage, a swollen battery, or loose hinges, and it cannot tell whether a laptop is reported stolen. Autopilot locks can stay hidden until the PC is reset, so the only 100% test is watching the seller reset it while connected to the internet. The hands-on page and checklist cover what software can't.

## Ideas for later

- A bootable USB guide (Ventoy + MemTest86 + live Linux) for when Windows can't be trusted or the seller won't allow software
- A game console checklist (PS5 / Xbox / Switch)
- Real temperatures and fan speeds via LibreHardwareMonitor
- A built-in GPU stress test
- Repair-cost estimates next to each problem
- A page comparing every laptop you have checked

## Licence

MIT, see [LICENSE](LICENSE).
