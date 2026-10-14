"""Cyber-themed desktop dashboard for the local network monitoring agent."""

import json
import queue
import threading
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from datetime import datetime
from tkinter import messagebox, ttk
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import urlopen

import network_threat_detection as agent


BG = "#07111f"
PANEL = "#0d1a2b"
PANEL_LIGHT = "#11243a"
LINE = "#1d3650"
TEXT = "#e6f0fa"
MUTED = "#8196ad"
CYAN = "#40d9ff"
GREEN = "#3ce6a0"
AMBER = "#ffbd59"
RED = "#ff617a"


class NetworkAgentDashboard:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("NEXUS  /  درع الشبكة المحلي")
        self.root.geometry("1180x780")
        self.root.minsize(940, 650)
        self.root.configure(bg=BG)

        self.events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.stop_event: Optional[threading.Event] = None
        self.monitor_thread: Optional[threading.Thread] = None
        self.monitor_active = False
        self.scan_count = 0
        self.alert_count = 0
        self.ai_busy = False

        self._configure_styles()
        self._build_layout()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(150, self._drain_events)
        self.root.after(350, self._check_ollama)

    def _configure_styles(self) -> None:
        self.font_small = tkfont.Font(family="Segoe UI", size=9)
        self.font_heading = tkfont.Font(family="Segoe UI Semibold", size=19)
        self.font_number = tkfont.Font(family="Segoe UI Semibold", size=25)
        self.font_mono = tkfont.Font(family="Cascadia Code", size=9)

        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Cyber.Treeview",
            background=PANEL,
            fieldbackground=PANEL,
            foreground=TEXT,
            borderwidth=0,
            rowheight=27,
            font=self.font_small,
        )
        style.configure(
            "Cyber.Treeview.Heading",
            background=PANEL_LIGHT,
            foreground=CYAN,
            relief="flat",
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "Cyber.Treeview",
            background=[("selected", "#15344c")],
            foreground=[("selected", TEXT)],
        )
        style.configure(
            "Cyber.TCombobox",
            fieldbackground=PANEL_LIGHT,
            background=PANEL_LIGHT,
            foreground=TEXT,
            arrowcolor=CYAN,
            bordercolor=LINE,
            lightcolor=LINE,
            darkcolor=LINE,
            padding=6,
        )
        style.map(
            "Cyber.TCombobox",
            fieldbackground=[("readonly", PANEL_LIGHT)],
            foreground=[("readonly", TEXT)],
            selectbackground=[("readonly", PANEL_LIGHT)],
            selectforeground=[("readonly", TEXT)],
        )

    def _build_layout(self) -> None:
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill="both", expand=True, padx=24, pady=(18, 14))

        header = tk.Frame(outer, bg=BG)
        header.pack(fill="x", pady=(0, 18))

        brand = tk.Frame(header, bg=BG)
        brand.pack(side="left", fill="x", expand=True)
        tk.Label(
            brand,
            text="NEXUS",
            bg=BG,
            fg=CYAN,
            font=("Segoe UI Semibold", 11),
        ).pack(anchor="w")
        tk.Label(
            brand,
            text="درع الشبكة المحلي  /  LOCAL NETWORK DEFENSE",
            bg=BG,
            fg=TEXT,
            font=self.font_heading,
        ).pack(anchor="w", pady=(1, 0))
        tk.Label(
            brand,
            text="خصوصية محلية  •  بيانات وصفية للاتصالات فقط",
            bg=BG,
            fg=MUTED,
            font=self.font_small,
        ).pack(anchor="w", pady=(4, 0))

        live_box = tk.Frame(header, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        live_box.pack(side="right", padx=(12, 0), pady=5)
        self.live_dot = tk.Label(live_box, text="●", bg=PANEL, fg=MUTED, font=("Segoe UI", 12))
        self.live_dot.pack(side="left", padx=(13, 7), pady=10)
        self.live_label = tk.Label(
            live_box, text="جاهز", bg=PANEL, fg=MUTED, font=("Segoe UI Semibold", 9)
        )
        self.live_label.pack(side="left", padx=(0, 14), pady=10)

        self.ollama_label = tk.Label(
            header,
            text="OLLAMA  •  جارٍ التحقق",
            bg=BG,
            fg=AMBER,
            font=("Segoe UI Semibold", 9),
        )
        self.ollama_label.pack(side="right", padx=(10, 2), pady=15)

        controls = tk.Frame(outer, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        controls.pack(fill="x", pady=(0, 14))
        controls_left = tk.Frame(controls, bg=PANEL)
        controls_left.pack(side="left", fill="x", expand=True, padx=15, pady=12)
        tk.Label(
            controls_left, text="فاصل الفحص", bg=PANEL, fg=MUTED, font=self.font_small
        ).pack(side="left", padx=(0, 9))
        self.interval_var = tk.StringVar(value=str(agent.POLL_SECONDS))
        self.interval_box = ttk.Combobox(
            controls_left,
            textvariable=self.interval_var,
            values=("3", "5", "10", "15", "30"),
            width=5,
            state="readonly",
            style="Cyber.TCombobox",
        )
        self.interval_box.pack(side="left")
        tk.Label(controls_left, text="ث", bg=PANEL, fg=MUTED, font=self.font_small).pack(
            side="left", padx=(6, 18)
        )

        self.ai_var = tk.BooleanVar(value=agent.AI_ENABLED)
        self.ai_check = tk.Checkbutton(
            controls_left,
            text="تحليل الذكاء الاصطناعي المحلي",
            variable=self.ai_var,
            bg=PANEL,
            fg=TEXT,
            activebackground=PANEL,
            activeforeground=CYAN,
            selectcolor=PANEL_LIGHT,
            font=("Segoe UI Semibold", 9),
            bd=0,
            highlightthickness=0,
        )
        self.ai_check.pack(side="left")

        buttons = tk.Frame(controls, bg=PANEL)
        buttons.pack(side="right", padx=12, pady=9)
        self.start_button = tk.Button(
            buttons,
            text="▶   بدء المراقبة",
            command=self.start_monitor,
            bg="#0d665c",
            fg="#eafff6",
            activebackground="#138272",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=16,
            pady=9,
            cursor="hand2",
            font=("Segoe UI Semibold", 9),
        )
        self.start_button.pack(side="left", padx=(0, 8))
        self.stop_button = tk.Button(
            buttons,
            text="■   إيقاف",
            command=self.stop_monitor,
            bg="#302231",
            fg="#a99aa8",
            activebackground="#5b2839",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=15,
            pady=9,
            cursor="hand2",
            font=("Segoe UI Semibold", 9),
            state="disabled",
        )
        self.stop_button.pack(side="left")

        metrics = tk.Frame(outer, bg=BG)
        metrics.pack(fill="x", pady=(0, 14))
        self.metric_values: Dict[str, tk.Label] = {}
        cards = (
            ("اتصالات نشطة", "active", CYAN),
            ("اتصالات بعيدة", "remote", GREEN),
            ("وجهات جديدة", "new", AMBER),
            ("تنبيهات محتملة", "alerts", RED),
        )
        for index, (title, key, accent) in enumerate(cards):
            metrics.grid_columnconfigure(index, weight=1, uniform="metric")
            card = tk.Frame(metrics, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 7, 0 if index == 3 else 7))
            tk.Frame(card, bg=accent, height=2).pack(fill="x")
            tk.Label(card, text=title, bg=PANEL, fg=MUTED, font=("Segoe UI Semibold", 8)).pack(
                anchor="w", padx=13, pady=(11, 1)
            )
            value = tk.Label(card, text="—", bg=PANEL, fg=TEXT, font=self.font_number)
            value.pack(anchor="w", padx=12, pady=(0, 9))
            self.metric_values[key] = value

        workspace = tk.Frame(outer, bg=BG)
        workspace.pack(fill="both", expand=True)
        workspace.grid_columnconfigure(0, weight=6, uniform="content")
        workspace.grid_columnconfigure(1, weight=5, uniform="content")
        workspace.grid_rowconfigure(0, weight=1)

        left = tk.Frame(workspace, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        self._section_header(left, "الاتصالات الحالية", "تتحدث مع كل فحص")
        columns = ("process", "remote", "status")
        self.connections = ttk.Treeview(
            left, columns=columns, show="headings", style="Cyber.Treeview", height=10
        )
        self.connections.heading("process", text="العملية")
        self.connections.heading("remote", text="العنوان البعيد")
        self.connections.heading("status", text="الحالة")
        self.connections.column("process", width=135, minwidth=95, stretch=True)
        self.connections.column("remote", width=180, minwidth=135, stretch=True)
        self.connections.column("status", width=92, minwidth=75, stretch=False, anchor="center")
        self.connections.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        activity = tk.Frame(left, bg=PANEL)
        activity.pack(fill="x", padx=12, pady=(3, 11))
        self._section_header(activity, "سجل الأحداث", "محلي")
        self.event_text = tk.Text(
            activity,
            height=6,
            bg="#091421",
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat",
            wrap="word",
            font=self.font_mono,
            padx=9,
            pady=7,
            state="disabled",
        )
        self.event_text.tag_configure("time", foreground=MUTED)
        self.event_text.tag_configure("normal", foreground=TEXT)
        self.event_text.tag_configure("alert", foreground=AMBER)
        self.event_text.tag_configure("error", foreground=RED)
        self.event_text.tag_configure("success", foreground=GREEN)
        self.event_text.pack(fill="x")

        right = tk.Frame(workspace, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        right.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        self._section_header(right, "تحليل التنبيه المحلي", agent.AI_MODEL)
        self.ai_text = tk.Text(
            right,
            bg="#091421",
            fg="#c7d6e5",
            insertbackground=CYAN,
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
            padx=14,
            pady=12,
            state="disabled",
        )
        self.ai_text.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.ai_text.configure(state="normal")
        self.ai_text.insert(
            "end",
            "النظام جاهز\n\n"
            "ابدأ المراقبة لفحص بيانات الاتصالات المحلية. عند ظهور تنبيه، "
            "يمكن للنموذج المحلي إعداد شرح موجز وحذر.\n\n"
            "يبقى تحليل الذكاء الاصطناعي على هذا الجهاز؛ لا تُرسل بيانات الاتصال إلى خدمة سحابية.\n\n"
            "التنبيهات مؤشرات للفحص وليست دليلًا قاطعًا على وجود هجوم.",
        )
        self.ai_text.configure(state="disabled")

        footer = tk.Frame(outer, bg=BG)
        footer.pack(fill="x", pady=(11, 0))
        self.status_text = tk.Label(
            footer,
            text="جاهز  •  لن تبدأ المراقبة حتى تضغط زر البدء",
            bg=BG,
            fg=MUTED,
            font=self.font_small,
        )
        self.status_text.pack(side="left")
        reports_button = tk.Button(
            footer,
            text="فتح التقارير",
            command=self.open_reports,
            bg=BG,
            fg=CYAN,
            activebackground=BG,
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Segoe UI Semibold", 8),
        )
        reports_button.pack(side="right")

    def _section_header(self, parent: tk.Widget, title: str, detail: str) -> None:
        bar = tk.Frame(parent, bg=PANEL)
        bar.pack(fill="x", padx=12, pady=(11, 9))
        tk.Label(bar, text=title, bg=PANEL, fg=TEXT, font=("Segoe UI Semibold", 9)).pack(
            side="left"
        )
        tk.Label(bar, text=detail.upper(), bg=PANEL, fg=CYAN, font=("Segoe UI", 8)).pack(
            side="right"
        )

    def start_monitor(self) -> None:
        if self.monitor_active:
            return
        try:
            interval = int(self.interval_var.get())
            if interval < 3:
                raise ValueError
        except ValueError:
            messagebox.showerror("فاصل فحص غير صالح", "اختر فاصلًا لا يقل عن 3 ثوانٍ.")
            return

        self.monitor_active = True
        self.stop_event = threading.Event()
        self.start_button.configure(state="disabled", bg="#17352f", fg="#72877f")
        self.stop_button.configure(state="normal", bg="#7c2d43", fg="white")
        self.interval_box.configure(state="disabled")
        self.ai_check.configure(state="disabled")
        self._set_live(True)
        self.status_text.configure(text="جارٍ بدء مراقبة الاتصالات…", fg=CYAN)
        self._add_event("بدأت المراقبة؛ بيانات وصفية للاتصالات فقط.", "success")

        self.monitor_thread = threading.Thread(
            target=self._monitor_worker,
            args=(interval, self.ai_var.get(), self.stop_event),
            name="network-monitor",
            daemon=True,
        )
        self.monitor_thread.start()

    def _monitor_worker(self, interval: int, ai_enabled: bool, stop_event: threading.Event) -> None:
        try:
            agent.run_monitor(
                interval,
                False,
                ai_enabled,
                on_update=self.events.put,
                stop_event=stop_event,
            )
        except Exception as exc:
            self.events.put({"type": "error", "message": f"{type(exc).__name__}: {exc}"})

    def stop_monitor(self) -> None:
        if self.stop_event is not None:
            self.stop_event.set()
            self.status_text.configure(text="سيتم الإيقاف بعد الفحص الحالي…", fg=AMBER)
            self.stop_button.configure(state="disabled")

    def _drain_events(self) -> None:
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            self._handle_event(event)
        self.root.after(150, self._drain_events)

    def _handle_event(self, event: Dict[str, Any]) -> None:
        event_type = event.get("type")
        if event_type == "snapshot":
            self._update_snapshot(event["snapshot"], event["summary"])
        elif event_type == "alert":
            self._show_alert(event["event"])
        elif event_type == "ai_result":
            if event.get("success"):
                self._show_ai_result(event)
            else:
                self.ai_busy = False
                self._add_event(f"Local AI unavailable: {event.get('analysis', 'unknown error')}", "error")
                self.status_text.configure(text="المراقبة تعمل  •  تحليل الذكاء الاصطناعي المحلي غير متاح", fg=AMBER)
        elif event_type == "error":
            self._add_event(event.get("message", "حدث خطأ في المراقبة"), "error")
            self.status_text.configure(text="خطأ في المراقبة  •  راجع سجل التشغيل المحلي", fg=RED)
            self._set_monitor_stopped()
        elif event_type == "ollama_status":
            self.ollama_label.configure(text=event["text"], fg=event["color"])
        elif event_type == "stopped":
            self._set_monitor_stopped()

    def _update_snapshot(self, snapshot: Dict[str, Any], summary: Dict[str, Any]) -> None:
        self.scan_count += 1
        self.metric_values["active"].configure(text=str(summary["active_connections"]))
        self.metric_values["remote"].configure(text=str(summary["total_remote_connections"]))
        self.metric_values["new"].configure(text=str(summary["new_destinations"]))
        self.metric_values["alerts"].configure(text=str(self.alert_count))
        self._refresh_connections(summary.get("sample_connections", []))
        self.status_text.configure(
            text=f"المراقبة تعمل  •  الفحص {self.scan_count}  •  "
            f"آخر تحديث {snapshot.get('observed_at', '')}",
            fg=GREEN,
        )

    def _refresh_connections(self, connections: List[Dict[str, Any]]) -> None:
        for row in self.connections.get_children():
            self.connections.delete(row)
        for item in connections[:20]:
            remote = f"{item.get('remote_ip', '')}:{item.get('remote_port', '')}"
            self.connections.insert(
                "",
                "end",
                values=(item.get("process", "unknown"), remote, item.get("status", "UNKNOWN")),
            )

    def _show_alert(self, event: Dict[str, Any]) -> None:
        alerts = event.get("alerts", [])
        if not alerts:
            return
        self.alert_count += len(alerts)
        self.metric_values["alerts"].configure(text=str(self.alert_count))
        for alert in alerts:
            self._add_event(f"اشتباه شذوذ  •  {alert['detail']}", "alert")
        self.status_text.configure(text="رُصد اشتباه شذوذ  •  راجع سجل الأحداث", fg=AMBER)
        ai_status = event.get("ai_status")
        if ai_status == "submitted":
            self.ai_busy = True
            self.ai_text.configure(state="normal")
            self.ai_text.delete("1.0", "end")
            self.ai_text.insert(
                "end",
                "وصل تنبيه\n\n"
                "يُعد النموذج المحلي شرحًا للتنبيه. ستستمر المراقبة أثناء التحليل.\n\n"
                "التنبيه مؤشر للفحص وليس دليلًا قاطعًا على وجود هجوم.",
            )
            self.ai_text.configure(state="disabled")
            self._add_event("أُرسل التنبيه إلى Ollama المحلي لإعداده للتحليل.", "normal")
        elif ai_status == "busy":
            self._add_event("حُفظ التنبيه؛ النموذج المحلي ما زال يحلل التنبيه السابق.", "normal")
        elif ai_status == "cooldown":
            self._add_event("حُفظ التنبيه؛ مهلة التهدئة لتحليل الذكاء الاصطناعي ما زالت فعالة.", "normal")
        else:
            self._add_event("حُفظ التنبيه. تحليل الذكاء الاصطناعي المحلي متوقف.", "normal")

    def _show_ai_result(self, event: Dict[str, Any]) -> None:
        self.ai_busy = False
        self.ai_text.configure(state="normal")
        self.ai_text.delete("1.0", "end")
        self.ai_text.insert("end", "تحليل النموذج المحلي\n\n")
        self.ai_text.insert("end", event.get("analysis", "No explanation was returned."))
        self.ai_text.insert("end", "\n\n")
        self.ai_text.insert("end", "\n\nالنتيجة اشتباه فقط؛ تحقّق من العملية والاتصال بشكل مستقل.")
        self.ai_text.configure(state="disabled")
        self._add_event(f"Local AI explanation saved: {event.get('report', '')}", "success")
        self.status_text.configure(text="المراقبة تعمل  •  اكتمل شرح الذكاء الاصطناعي المحلي", fg=GREEN)

    def _add_event(self, message: str, tag: str = "normal") -> None:
        self.event_text.configure(state="normal")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.event_text.insert("end", f"{timestamp}  ", "time")
        self.event_text.insert("end", message + "\n", tag)
        line_count = int(self.event_text.index("end-1c").split(".")[0])
        if line_count > 80:
            self.event_text.delete("1.0", f"{line_count - 80}.0")
        self.event_text.see("end")
        self.event_text.configure(state="disabled")

    def _set_live(self, active: bool) -> None:
        self.live_dot.configure(fg=GREEN if active else MUTED)
        self.live_label.configure(
            text="مراقبة مباشرة" if active else "جاهز",
            fg=GREEN if active else MUTED,
        )

    def _set_monitor_stopped(self) -> None:
        self.monitor_active = False
        self.stop_event = None
        self.start_button.configure(state="normal", bg="#0d665c", fg="#eafff6")
        self.stop_button.configure(state="disabled", bg="#302231", fg="#a99aa8")
        self.interval_box.configure(state="readonly")
        self.ai_check.configure(state="normal")
        self._set_live(False)
        self.status_text.configure(text="Monitoring stopped  •  Press Start when you are ready", fg=MUTED)

    def _check_ollama(self) -> None:
        threading.Thread(target=self._probe_ollama, name="ollama-status-check", daemon=True).start()
        self.root.after(30000, self._check_ollama)

    def _probe_ollama(self) -> None:
        try:
            with urlopen(f"{agent.OLLAMA_URL}/api/tags", timeout=3) as response:
                models = json.loads(response.read().decode("utf-8")).get("models", [])
            available = any(
                model.get("name") == agent.AI_MODEL or model.get("name", "").startswith(agent.AI_MODEL + ":")
                for model in models
            )
            text = f"OLLAMA  •  {agent.AI_MODEL} {'جاهز' if available else 'النموذج غير موجود'}"
            color = GREEN if available else AMBER
        except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
            text = "OLLAMA  •  غير متصل"
            color = RED
        self.events.put({"type": "ollama_status", "text": text, "color": color})

    def open_reports(self) -> None:
        agent.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        webbrowser.open(agent.REPORTS_DIR.as_uri())

    def _on_close(self) -> None:
        if self.monitor_active and self.stop_event is not None:
            self.stop_event.set()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    NetworkAgentDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
