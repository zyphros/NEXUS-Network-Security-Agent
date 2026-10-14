# NEXUS — Local Network Security Agent

**A lightweight Windows desktop dashboard for monitoring network connection metadata, with optional, private AI explanations from a local Ollama model.**

> This project is an educational monitoring prototype. It reports rule-based indicators for human review; it is not a complete intrusion-detection system and does not prove that an attack is occurring.

## Highlights

- Cyber-themed desktop dashboard with start/stop controls, live counters, a connection table, event feed, and local AI analysis panel.
- Monitors Windows network connection metadata using `psutil`; no packet payloads, browsing contents, or credentials are collected.
- Applies explainable connection-count thresholds and a cooldown to reduce repeated alerts.
- Optionally explains alerts with Ollama on the same device. No cloud AI API or API key is required.
- Keeps monitoring responsive while the local model generates an explanation.
- Continues rule-based monitoring when Ollama is unavailable.
- Stores application logs and reports in a per-user local data directory, outside the repository.
- Uses bounded scans and a small, quantized 3B model by default to suit memory-constrained laptops.

## Screenshots

The application opens as a native Windows/Tkinter desktop window. Start the dashboard with the steps below to view the live interface.

## Requirements

- Windows 10/11
- Python 3.10 or later, including Tcl/Tk
- Ollama for local AI explanations (optional for connection monitoring)
- `qwen2.5:3b` in Ollama for the default local AI configuration

The default Qwen model is a quantized 3B model and downloads approximately 1.9 GB. AI inference uses local compute and may take time on a CPU-only laptop. The model is requested only when a rule-based alert occurs.

## Quick start

1. Install Python and, if you want AI explanations, install and start [Ollama](https://ollama.com/).
2. Download the model once:

   ```powershell
   ollama pull qwen2.5:3b
   ```

3. Double-click `setup_windows.bat` to create an isolated Python environment in your user profile and install the lightweight `psutil` dependency.
4. Double-click `run_dashboard.bat` to open the interface.
5. Press **Start Monitoring** in the dashboard. Monitoring does not start until you press the button. Stop it with **Stop** or close the window.

To use the terminal monitor instead of the dashboard:

```powershell
run_agent.bat --once --no-ai
run_agent.bat --interval 10
```

The first command performs one lightweight scan without AI; the second starts continuous monitoring with a 10-second interval.

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
| `MAX_CONNECTIONS_ALERT` | `150` | Established-connection alert threshold |
| `MAX_NEW_DESTINATIONS_ALERT` | `25` | New remote IP/port pairs per scan |
| `MAX_PROCESS_CONNECTIONS_ALERT` | `80` | Remote connections per process |

Increase `POLL_SECONDS` to reduce scan frequency. Rule thresholds are configurable heuristics and may need adjustment for a particular device.

## Repository layout

```text
.
├── network_agent_gui.py       # Native Tkinter desktop dashboard
├── network_threat_detection.py # Connection collection and rule-based monitoring
├── requirements.txt           # Minimal Python dependency
├── .env.example               # Safe configuration template
├── .gitignore                 # Excludes secrets and generated runtime data
├── setup_windows.bat          # First-time local setup
├── run_dashboard.bat          # Launch the GUI
├── run_agent.bat              # Launch the CLI monitor
└── setup_check.bat            # One-shot connection and Ollama check
```

## Data and privacy

- Connection snapshots include remote/local addresses and ports, process names when Windows permits access, and connection state.
- The tool does not capture packet content, passwords, browser history, or credentials; it does not block connections or change firewall settings.
- Optional AI explanations are sent only to the configured local Ollama service. Do not change `OLLAMA_URL` to a remote host if you intend to keep data on the device.
- Logs and generated reports are stored under `%USERPROFILE%\.network_security_agent\data`, not in this repository.
- `.env`, virtual environments, logs, reports, model files, and databases are excluded by `.gitignore`. Review `git status` before publishing.

## Limitations

- This is connection-metadata monitoring, not packet capture or a full endpoint/network security product.
- Short-lived connections may start and end between scans.
- Windows can restrict visibility into protected processes; the dashboard may show fewer connections without administrator permissions.
- Threshold alerts can be false positives and should be investigated before drawing conclusions.
- Local AI output is generated text, may be incorrect, and is advisory only. The program does not take automatic response actions.
- Ollama inference may use significant CPU and memory while generating a report; it runs only after an alert and uses bounded generation settings.

## Tests

The rule detector and dashboard can be smoke-tested with the installed environment:

```powershell
python -m py_compile network_threat_detection.py network_agent_gui.py
python -m unittest discover -s tests -v
python network_threat_detection.py --once --no-ai
```

## العربية

**NEXUS** تطبيق مكتبي محلي لنظام Windows لمراقبة البيانات الوصفية لاتصالات الشبكة، مع شرح اختياري للتنبيهات بواسطة نموذج Ollama محلي.

- واجهة عربية بتصميم سيبراني تعرض الاتصالات والعدادات والتنبيهات.
- لا يلتقط محتوى الحزم أو كلمات المرور ولا يغيّر إعدادات الشبكة.
- يعمل فحص الاتصالات دون Ollama؛ ويُستخدم النموذج المحلي عند ظهور تنبيه فقط.
- التقارير والسجلات تبقى في مجلد بيانات المستخدم، وليس داخل المستودع.
- التنبيهات مؤشرات تحتاج إلى مراجعة وليست إثباتًا على وجود هجوم.

للبدء: ثبّت Python وOllama، ثم شغّل `ollama pull qwen2.5:3b`، وبعدها `setup_windows.bat` ثم `run_dashboard.bat`. تبدأ المراقبة فقط بعد الضغط على زر البدء.

## License

No license is included yet. Add a license only after choosing the terms under which you want others to use or redistribute the project.
