# NEXUS — Local Network Security Agent

**A lightweight cross-platform desktop dashboard for monitoring network connection metadata, with optional AI explanations from a local Ollama model.**

`Windows` · `Linux` · `macOS` · `Python` · `Tkinter` · `psutil` · `Ollama (optional)`

[العربية](README.ar.md) · [Repository](https://github.com/zyphros/NEXUS-Network-Security-Agent)

> This project is an educational monitoring prototype. It reports rule-based indicators for human review; it is not a complete intrusion-detection system and does not prove that an attack is occurring.

## Dashboard preview

[![NEXUS desktop dashboard preview](docs/images/nexus-dashboard.png)](docs/images/nexus-dashboard.png)

*Dashboard screenshot from a local session. Remote addresses have been replaced with documentation-only example addresses.*

## Project at a glance

- **Purpose:** Make local network connection activity and simple rule-based alerts easy to inspect from a desktop dashboard.
- **Monitoring:** Reads connection metadata with `psutil`; it does not capture packet contents.
- **AI:** Optional Ollama can explain alerts or answer a dashboard question when requested.
- **Command center:** Ask questions about the current dashboard and use a small allowlist of in-app commands; arbitrary shell or operating-system commands are never executed.
- **Isolation:** Shows cautious, human-reviewed isolation recommendations for suspicious activity. NEXUS does not kill processes, block traffic, or change firewall settings.
- **Safety:** Monitoring starts only when the user presses Start. The app does not block traffic or change firewall settings.
- **Platforms:** Windows, Linux, and macOS for connection-metadata monitoring; Tkinter is required for the desktop dashboard.
- **Audience:** An educational, cross-platform portfolio project, not a production security product.

## Contents

- [Highlights](#highlights)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Repository layout](#repository-layout)
- [Data and privacy](#data-and-privacy)
- [Limitations](#limitations)
- [Tests](#tests)
- [Arabic documentation](README.ar.md)

## Highlights

- Cyber-themed desktop dashboard with start/stop controls, live counters, a connection table, event feed, and local AI analysis panel.
- Monitors network connection metadata exposed by Windows, Linux, or macOS through `psutil`; no packet payloads, browsing contents, or credentials are collected.
- Applies explainable connection-count thresholds and a cooldown to reduce repeated alerts.
- Optionally explains alerts with Ollama on the same device. No cloud AI API or API key is required.
- Keeps monitoring responsive while the local model generates an explanation or answer.
- Continues rule-based monitoring when Ollama is unavailable.
- Offers an in-app command center for status, recent alerts, sampled connections, advisory isolation guidance, reports, and start/stop controls.
- Adds cautious isolation recommendations to alerts without performing enforcement; any response remains an authorized operator's responsibility.
- Optionally ingests warning-and-higher Syslog UDP messages and Wazuh `alerts.json` records as read-only events.
- Stores application logs and reports in a per-user local data directory, outside the repository.
- Uses bounded scans and a small, quantized 3B model by default to suit memory-constrained laptops.

## Requirements

- Windows 10/11, Linux, or macOS
- Python 3.10 or later, including Tcl/Tk
- Ollama for local AI explanations (optional for connection monitoring)
- `qwen2.5:3b` in Ollama for the default local AI configuration

The default Qwen model is a quantized 3B model and downloads approximately 1.9 GB. AI inference uses local compute and may take time on a CPU-only laptop. The model is requested only when a rule-based alert occurs.

## Quick start

1. Install Python 3.10+ with Tk/Tcl support. On Linux, install your distribution's Tk package (commonly `python3-tk`) if it is not included. Install and start [Ollama](https://ollama.com/) only if you want AI explanations.
2. Download the model once:

   ```powershell
   ollama pull qwen2.5:3b
   ```

3. On Windows, double-click `setup_windows.bat`. On Linux or macOS, run `bash setup_unix.sh`. Both create an isolated Python environment in your user home and install `psutil`.
4. On Windows, double-click `run_dashboard.bat`. On Linux or macOS, run `bash run_dashboard.sh`.
5. Press **Start Monitoring** in the dashboard. Monitoring does not start until you press the button. Stop it with **Stop** or close the window.

To use the terminal monitor instead of the dashboard, use `run_agent.bat` on Windows or `bash run_agent.sh` on Linux/macOS:

```powershell
run_agent.bat --once --no-ai
run_agent.bat --interval 10
```

The first command performs one lightweight scan without AI; the second starts continuous monitoring with a 10-second interval. The same flags work with `bash run_agent.sh`.

## Configuration

Copy `.env.example` to `.env` and edit only the settings you need. `.env` is excluded from Git by `.gitignore`.

| Setting | Default | Purpose |
| --- | --- | --- |
| `POLL_SECONDS` | `5` | Seconds between connection snapshots |
| `AI_ENABLED` | `true` | Enable optional local Ollama explanations |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Local Ollama endpoint |
| `AI_MODEL` | `qwen2.5:3b` | Installed Ollama model name |
| `AI_COOLDOWN_SECONDS` | `300` | Minimum time between AI requests |
| `AI_TIMEOUT_SECONDS` | `120` | Maximum wait for an AI response |
| `SYSLOG_UDP_ENABLED` | `false` | Enable the optional Syslog UDP listener |
| `SYSLOG_UDP_HOST` | `127.0.0.1` | Interface address for the UDP listener |
| `SYSLOG_UDP_PORT` | `5514` | UDP listener port |
| `SYSLOG_UDP_MAX_SEVERITY` | `4` | Highest numeric Syslog severity reported (0 is most severe) |
| `WAZUH_ALERTS_FILE` | empty | Optional path to a Wazuh `alerts.json` file |
| `WAZUH_MINIMUM_LEVEL` | `7` | Minimum Wazuh rule level reported |
| `MAX_CONNECTIONS_ALERT` | `150` | Established-connection alert threshold |
| `MAX_NEW_DESTINATIONS_ALERT` | `25` | New remote IP/port pairs per scan |
| `MAX_PROCESS_CONNECTIONS_ALERT` | `80` | Remote connections per process |

Increase `POLL_SECONDS` to reduce scan frequency. Rule thresholds are configurable heuristics and may need adjustment for a particular device.

## Security event integrations (optional)

The first integration layer supports two read-only inputs:

- **Syslog UDP:** disabled by default, binds to `127.0.0.1:5514` when enabled, and raises dashboard alerts for messages at warning severity or higher (Syslog PRI severity `0`–`4`).
- **Wazuh JSON alerts:** tails new records appended to a local or mounted `alerts.json` file and reports alerts at level `7` or higher by default. Existing records are not replayed on startup.

Add only the input you need to the local `.env` file. Example for a Wazuh manager file readable from this machine (use the actual mounted/share path on Windows):

```dotenv
WAZUH_ALERTS_FILE=C:\wazuh-share\alerts.json
WAZUH_MINIMUM_LEVEL=7
```

Example for a local Syslog sender:

```dotenv
SYSLOG_UDP_ENABLED=true
SYSLOG_UDP_HOST=127.0.0.1
SYSLOG_UDP_PORT=5514
SYSLOG_UDP_MAX_SEVERITY=4
```

For remote forwarding, set `SYSLOG_UDP_HOST` to an explicitly selected interface and configure the sender and host firewall yourself. Syslog UDP is unauthenticated and unencrypted: keep it on a trusted, segmented management network or use a protected relay/VPN; never expose the listener directly to the public internet. Validate the sender path before deployment. The receiver queues at most 500 events and handles at most 25 actionable events per monitor cycle to bound resource use.

## Cross-platform support

The connection collector and read-only Syslog/Wazuh ingestion are designed for Windows, Linux, and macOS. The desktop UI additionally requires a Python installation with Tkinter/Tcl-Tk available; Linux distributions may package Tk separately. OS permissions and platform APIs affect which process and connection details `psutil` can expose. The project does not currently provide OS-specific endpoint-security or firewall control integrations. It can suggest review steps, but it does not isolate processes or devices.

GitHub Actions runs the syntax checks and unit tests on Windows, Ubuntu Linux, and macOS. This CI coverage verifies the shared monitoring code and integrations; it is not a claim that every distribution, desktop environment, security product, or data-center platform is supported.

`AI_MODEL` can select another model available through the Ollama API, including a compatible security-tuned model. The default `qwen2.5:3b` is a small general-purpose model, not a validated cybersecurity model. Evaluate any alternative against representative, sanitized data before relying on its explanations. AI text is advisory and never triggers a response action.

## Repository layout

```text
.
├── network_agent_gui.py       # Native Tkinter desktop dashboard
├── network_threat_detection.py # Connection collection and rule-based monitoring
├── command_center.py          # Allowlisted dashboard commands and advisory guidance
├── security_event_ingest.py   # Bounded Syslog UDP and Wazuh JSON inputs
├── setup_unix.sh              # Linux/macOS Python environment setup
├── run_dashboard.sh           # Linux/macOS desktop launch
├── run_agent.sh               # Linux/macOS terminal launch
├── requirements.txt           # Minimal Python dependency
├── .env.example               # Safe configuration template
├── .gitignore                 # Excludes secrets and generated runtime data
├── docs/images/
│   └── nexus-dashboard.png    # Redacted dashboard preview
├── tests/
│   ├── test_command_center.py  # Command allowlist, question, and recommendation tests
│   ├── test_rule_detector.py  # Rule-detector unit tests
│   └── test_security_event_ingest.py # Integration input tests
├── .github/workflows/
│   └── cross-platform-tests.yml # Windows, Ubuntu, and macOS test matrix
├── README.md                  # English project guide
├── README.ar.md               # Arabic project guide
├── setup_windows.bat          # First-time local setup
├── run_dashboard.bat          # Launch the GUI
├── run_agent.bat              # Launch the CLI monitor
└── setup_check.bat            # One-shot connection and Ollama check
```

## Data and privacy

- Connection snapshots include remote/local addresses and ports, process names when the operating system permits access, and connection state.
- Enabled integrations may include security-event descriptions, sender/source IPs, rule IDs, severity, and agent names in local reports. Review and protect these files as security-sensitive data.
- The tool does not capture packet content, passwords, browser history, or credentials; it does not block connections or change firewall settings.
- Optional AI explanations and free-form dashboard questions are sent only to the configured Ollama endpoint. Keep `OLLAMA_URL` local if you intend to keep data on the device.
- Recent free-form Q&A history is kept in memory for follow-up questions only; it is not written to disk by the command center.
- The command center recognizes fixed in-app commands and common status/alert questions offline (help, status, alerts, connections, recommendations, start/stop monitoring, and reports). Other text is a question for Ollama; no shell or operating-system command is executed.
- Isolation guidance is advisory. NEXUS does not terminate processes, block connections, apply firewall rules, or isolate a device.
- Logs and generated reports are stored under `~/.network_security_agent/data`, not in this repository.
- `.env`, virtual environments, logs, reports, model files, and databases are excluded by `.gitignore`. Review `git status` before publishing.

## Limitations

- This is connection-metadata monitoring, not packet capture or a full endpoint/network security product.
- Integrations currently cover Syslog UDP and Wazuh JSON file tailing only; this is not a universal SIEM/EDR connector, a clustered data-center service, or a high-availability event pipeline.
- The Wazuh file input must be readable from the machine running NEXUS. Network shares, permissions, event delivery, and firewall rules must be configured and secured by the operator.
- Syslog UDP does not authenticate senders or encrypt traffic. Use it only on a trusted network or through a protected relay.
- The project does not manage encryption keys, configure cryptographic systems, isolate endpoints, or enforce security policies; isolation recommendations require independent verification and an authorized response process.
- Short-lived connections may start and end between scans.
- Operating-system permissions can restrict visibility into protected processes; the dashboard may show fewer connections without elevated permissions.
- Threshold alerts can be false positives and should be investigated before drawing conclusions.
- Local AI output is generated text, may be incorrect, and is advisory only. The program does not take automatic response actions.
- Ollama inference may use significant CPU and memory while generating a report; it runs only after an alert and uses bounded generation settings.

## Tests

The rule detector and dashboard can be smoke-tested with the installed environment:

```sh
python -m py_compile network_threat_detection.py network_agent_gui.py security_event_ingest.py command_center.py
python -m unittest discover -s tests -v
python network_threat_detection.py --once --no-ai
```

## العربية

**NEXUS** تطبيق مكتبي محلي متعدد الأنظمة لمراقبة البيانات الوصفية لاتصالات الشبكة، مع شرح اختياري للتنبيهات بواسطة نموذج Ollama محلي.

- واجهة عربية بتصميم سيبراني تعرض الاتصالات والعدادات والتنبيهات.
- لا يلتقط محتوى الحزم أو كلمات المرور ولا يغيّر إعدادات الشبكة.
- يعمل فحص الاتصالات دون Ollama؛ ويُستخدم النموذج المحلي عند ظهور تنبيه فقط.
- التقارير والسجلات تبقى في مجلد بيانات المستخدم، وليس داخل المستودع.
- التنبيهات مؤشرات تحتاج إلى مراجعة وليست إثباتًا على وجود هجوم.

للبدء: ثبّت Python وOllama، ثم شغّل `ollama pull qwen2.5:3b`. في Windows استخدم `setup_windows.bat` و`run_dashboard.bat`؛ وفي Linux/macOS استخدم `bash setup_unix.sh` و`bash run_dashboard.sh`. تبدأ المراقبة فقط بعد الضغط على زر البدء.

## License

Copyright © 2026 zyphros. All rights reserved.

No license is granted for using, copying, modifying, or distributing this project. Contact the copyright holder for permission.
