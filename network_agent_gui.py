"""Cyber-themed desktop dashboard for the local network monitoring agent."""

import json
import queue
import threading
import tkinter as tk
import tkinter.font as tkfont
import webbrowser
from datetime import datetime
from tkinter import messagebox, ttk
from urllib.error import URLError
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from urllib.request import urlopen

import network_threat_detection as agent
from command_center import isolation_recommendation, parse_command
from local_model_manager import (
    SUPPORTED_MODELS,
    installed_models,
    persist_model_selection,
    pull_model,
)
from web_research import MAX_QUERY_CHARS, search_web


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
        self.command_busy = False
        self.web_busy = False
        self.model_busy = False
        self.ollama_available = False
        self.available_models: set[str] = set()
        self.latest_snapshot: Dict[str, Any] = {}
        self.latest_summary: Dict[str, Any] = {}
        self.recent_alerts: List[Dict[str, Any]] = []
        self.recent_security_events: List[Dict[str, Any]] = []
        self.question_history: List[Dict[str, str]] = []

        self._configure_styles()
        self._build_layout()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(150, self._drain_events)
        self.root.after(350, self._check_ollama)
        self.root.after(500, self._refresh_models)

    def _configure_styles(self) -> None:
        self.font_family = tkfont.nametofont("TkDefaultFont", root=self.root).cget("family")
        self.mono_family = tkfont.nametofont("TkFixedFont", root=self.root).cget("family")
        self.font_small = tkfont.Font(family=self.font_family, size=9)
        self.font_heading = tkfont.Font(family=self.font_family, size=19, weight="bold")
        self.font_number = tkfont.Font(family=self.font_family, size=25, weight="bold")
        self.font_mono = tkfont.Font(family=self.mono_family, size=9)

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
            font=(self.font_family, 9, "bold"),
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
        style.configure(
            "Cyber.Horizontal.TProgressbar",
            troughcolor=PANEL_LIGHT,
            background=CYAN,
            bordercolor=LINE,
            lightcolor=CYAN,
            darkcolor=CYAN,
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
            font=(self.font_family, 11, "bold"),
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
        self.live_dot = tk.Label(live_box, text="●", bg=PANEL, fg=MUTED, font=(self.font_family, 12))
        self.live_dot.pack(side="left", padx=(13, 7), pady=10)
        self.live_label = tk.Label(
            live_box, text="جاهز", bg=PANEL, fg=MUTED, font=(self.font_family, 9, "bold")
        )
        self.live_label.pack(side="left", padx=(0, 14), pady=10)

        self.ollama_label = tk.Label(
            header,
            text="OLLAMA  •  جارٍ التحقق",
            bg=BG,
            fg=AMBER,
            font=(self.font_family, 9, "bold"),
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
            font=(self.font_family, 9, "bold"),
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
            font=(self.font_family, 9, "bold"),
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
            font=(self.font_family, 9, "bold"),
            state="disabled",
        )
        self.stop_button.pack(side="left")

        model_panel = tk.Frame(outer, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        model_panel.pack(fill="x", pady=(0, 14))
        model_controls = tk.Frame(model_panel, bg=PANEL)
        model_controls.pack(fill="x", padx=15, pady=10)
        tk.Label(
            model_controls, text="النموذج المحلي", bg=PANEL, fg=MUTED, font=self.font_small
        ).pack(side="left", padx=(0, 8))
        self.model_var = tk.StringVar(
            value=agent.AI_MODEL if agent.AI_MODEL in SUPPORTED_MODELS else SUPPORTED_MODELS[0]
        )
        self.model_box = ttk.Combobox(
            model_controls,
            textvariable=self.model_var,
            values=SUPPORTED_MODELS,
            width=16,
            state="readonly",
            style="Cyber.TCombobox",
        )
        self.model_box.pack(side="left", padx=(0, 8))
        self.model_box.bind("<<ComboboxSelected>>", self._on_model_choice)
        self.model_use_button = tk.Button(
            model_controls,
            text="استخدام المحدد",
            command=self._activate_selected_model,
            bg="#15344c",
            fg=TEXT,
            activebackground="#1b4965",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=11,
            pady=7,
            cursor="hand2",
            font=(self.font_family, 9, "bold"),
        )
        self.model_use_button.pack(side="left", padx=(0, 7))
        self.model_pull_button = tk.Button(
            model_controls,
            text="تنزيل المحدد",
            command=self._start_model_download,
            bg="#0d665c",
            fg="#eafff6",
            activebackground="#138272",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=11,
            pady=7,
            cursor="hand2",
            font=(self.font_family, 9, "bold"),
        )
        self.model_pull_button.pack(side="left", padx=(0, 10))
        self.model_status_label = tk.Label(
            model_controls,
            text="إدارة محلية اختيارية؛ لا يبدأ أي تنزيل تلقائيًا.",
            bg=PANEL,
            fg=MUTED,
            font=self.font_small,
            anchor="w",
        )
        self.model_status_label.pack(side="left", fill="x", expand=True)
        self.model_progress = ttk.Progressbar(
            model_panel, mode="determinate", maximum=100, style="Cyber.Horizontal.TProgressbar"
        )
        self.model_progress.pack(fill="x", padx=15, pady=(0, 10))

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
            tk.Label(card, text=title, bg=PANEL, fg=MUTED, font=(self.font_family, 8, "bold")).pack(
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
        self._section_header(right, "مساعد NEXUS", "محلي")
        assistant_tabs = ttk.Notebook(right)
        assistant_tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        ai_page = tk.Frame(assistant_tabs, bg=PANEL)
        assistant_tabs.add(ai_page, text="تحليل التنبيه")
        self.ai_text = tk.Text(
            ai_page,
            bg="#091421",
            fg="#c7d6e5",
            insertbackground=CYAN,
            relief="flat",
            wrap="word",
            font=(self.font_family, 10),
            padx=14,
            pady=12,
            state="disabled",
        )
        self.ai_text.pack(fill="both", expand=True, padx=5, pady=(5, 8))
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
        self.recommendation_text = tk.Text(
            ai_page,
            height=4,
            bg="#152233",
            fg=AMBER,
            relief="flat",
            wrap="word",
            font=(self.font_family, 9),
            padx=10,
            pady=8,
            state="disabled",
        )
        self.recommendation_text.pack(fill="x", padx=5, pady=(0, 5))
        self._set_recommendation(
            "اقتراحات العزل استشارية فقط؛ لا ينفذ NEXUS أي حظر أو تغيير للنظام."
        )

        command_page = tk.Frame(assistant_tabs, bg=PANEL)
        assistant_tabs.add(command_page, text="الأسئلة والأوامر")
        tk.Label(
            command_page,
            text=(
                "أوامر داخل التطبيق فقط: مساعدة، الحالة، التنبيهات، الاتصالات، "
                "التوصيات، ابدأ، أوقف، التقارير.\n"
                "الأسئلة الشائعة تعمل محليًا؛ الأسئلة الحرة تحتاج Ollama. "
                "لا تُنفذ أوامر النظام."
            ),
            bg=PANEL,
            fg=MUTED,
            justify="right",
            wraplength=500,
            font=self.font_small,
        ).pack(fill="x", padx=8, pady=(8, 4))
        self.command_text = tk.Text(
            command_page,
            bg="#091421",
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat",
            wrap="word",
            font=(self.font_family, 9),
            padx=10,
            pady=9,
            state="disabled",
        )
        self.command_text.tag_configure("user", foreground=CYAN)
        self.command_text.tag_configure("assistant", foreground=TEXT)
        self.command_text.tag_configure("error", foreground=RED)
        command_controls = tk.Frame(command_page, bg=PANEL)
        command_controls.pack(side="bottom", fill="x", padx=8, pady=(0, 8))
        self.command_entry = tk.Entry(
            command_controls,
            bg=PANEL_LIGHT,
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat",
            font=(self.font_family, 10),
        )
        self.command_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 7))
        self.command_entry.bind("<Return>", self.submit_command)
        self.command_send_button = tk.Button(
            command_controls,
            text="إرسال",
            command=self.submit_command,
            bg="#0d665c",
            fg="#eafff6",
            activebackground="#138272",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=12,
            pady=7,
            cursor="hand2",
            font=(self.font_family, 9, "bold"),
        )
        self.command_send_button.pack(side="right")
        self.command_text.pack(fill="both", expand=True, padx=8, pady=5)
        self._append_command_message(
            "NEXUS",
            "اكتب «مساعدة» لعرض الأوامر. يمكنك السؤال عن الحالة والتنبيهات؛ "
            "الأسئلة الشائعة تعمل دون Ollama، والأسئلة الحرة تحتاج Ollama المحلي.",
        )
        assistant_tabs.select(command_page)
        self.root.after_idle(self.command_entry.focus_set)

        research_page = tk.Frame(assistant_tabs, bg=PANEL)
        assistant_tabs.add(research_page, text="بحث الإنترنت")
        tk.Label(
            research_page,
            text=(
                "يُرسل نص البحث فقط إلى Bing. تُحلل المقتطفات عبر Ollama "
                "المحلي؛ لا تُرسل بيانات الاتصالات أو أسئلة اللوحة لمحرك البحث."
            ),
            bg=PANEL,
            fg=MUTED,
            justify="right",
            wraplength=500,
            font=self.font_small,
        ).pack(fill="x", padx=8, pady=(8, 5))
        research_controls = tk.Frame(research_page, bg=PANEL)
        research_controls.pack(fill="x", padx=8, pady=(0, 6))
        self.web_search_entry = tk.Entry(
            research_controls,
            bg=PANEL_LIGHT,
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat",
            font=(self.font_family, 10),
        )
        self.web_search_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 7))
        self.web_search_entry.bind("<Return>", self.submit_web_search)
        self.web_search_button = tk.Button(
            research_controls,
            text="بحث",
            command=self.submit_web_search,
            bg="#0d665c",
            fg="#eafff6",
            activebackground="#138272",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=12,
            pady=7,
            cursor="hand2",
            font=(self.font_family, 9, "bold"),
        )
        self.web_search_button.pack(side="right")
        self.web_analysis_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            research_page,
            text="تحليل النتائج محليًا عبر Ollama",
            variable=self.web_analysis_var,
            bg=PANEL,
            fg=TEXT,
            activebackground=PANEL,
            activeforeground=CYAN,
            selectcolor=PANEL_LIGHT,
            font=(self.font_family, 9, "bold"),
            bd=0,
            highlightthickness=0,
        ).pack(anchor="e", padx=8, pady=(0, 5))
        self.web_status_label = tk.Label(
            research_page,
            text="جاهز للبحث — لا يبدأ الاتصال حتى تضغط بحث.",
            bg=PANEL,
            fg=MUTED,
            anchor="e",
            font=self.font_small,
        )
        self.web_status_label.pack(fill="x", padx=8, pady=(0, 4))

        results_frame = tk.Frame(research_page, bg=PANEL)
        results_frame.pack(fill="both", expand=True, padx=8, pady=(0, 5))
        tk.Label(
            results_frame, text="نتائج البحث ومصادرها", bg=PANEL, fg=CYAN,
            anchor="e", font=(self.font_family, 9, "bold")
        ).pack(fill="x", pady=(0, 3))
        results_body = tk.Frame(results_frame, bg="#091421")
        results_body.pack(fill="both", expand=True)
        self.web_results_text = tk.Text(
            results_body,
            height=8,
            bg="#091421",
            fg=TEXT,
            insertbackground=CYAN,
            relief="flat",
            wrap="word",
            font=(self.font_family, 9),
            padx=9,
            pady=7,
            state="disabled",
        )
        results_scrollbar = ttk.Scrollbar(
            results_body, orient="vertical", command=self.web_results_text.yview
        )
        self.web_results_text.configure(yscrollcommand=results_scrollbar.set)
        self.web_results_text.pack(side="left", fill="both", expand=True)
        results_scrollbar.pack(side="right", fill="y")

        analysis_frame = tk.Frame(research_page, bg=PANEL)
        analysis_frame.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(
            analysis_frame, text="التحليل المحلي", bg=PANEL, fg=GREEN,
            anchor="e", font=(self.font_family, 9, "bold")
        ).pack(fill="x", pady=(0, 3))
        self.web_analysis_text = tk.Text(
            analysis_frame,
            height=5,
            bg="#091421",
            fg="#c7d6e5",
            relief="flat",
            wrap="word",
            font=(self.font_family, 9),
            padx=9,
            pady=7,
            state="disabled",
        )
        self.web_analysis_text.pack(fill="x")

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
            font=(self.font_family, 8, "bold"),
        )
        reports_button.pack(side="right")

    def _section_header(self, parent: tk.Widget, title: str, detail: str) -> None:
        bar = tk.Frame(parent, bg=PANEL)
        bar.pack(fill="x", padx=12, pady=(11, 9))
        tk.Label(bar, text=title, bg=PANEL, fg=TEXT, font=(self.font_family, 9, "bold")).pack(
            side="left"
        )
        tk.Label(bar, text=detail.upper(), bg=PANEL, fg=CYAN, font=(self.font_family, 8)).pack(
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
            self.ollama_available = bool(event.get("available"))
            self.ollama_label.configure(text=event["text"], fg=event["color"])
        elif event_type == "model_list":
            self.available_models = set(event["models"])
            selected = self.model_var.get()
            if selected in self.available_models:
                self.model_status_label.configure(
                    text=f"النموذج المحدد مثبت: {selected}",
                    fg=GREEN,
                )
            else:
                self.model_status_label.configure(
                    text=f"{selected} غير مثبت؛ اضغط «تنزيل المحدد» عند الحاجة.",
                    fg=AMBER,
                )
        elif event_type == "model_list_error":
            self.model_status_label.configure(text=event["message"], fg=RED)
        elif event_type == "model_pull_progress":
            update = event["update"]
            total = update.get("total")
            completed = update.get("completed")
            status = update.get("status", "جارٍ التنزيل")
            if type(total) is int and total > 0 and type(completed) is int:
                self.model_progress.configure(value=min(100, completed * 100 / total))
                status = f"{status}  •  {completed * 100 / total:.0f}% من الجزء الحالي"
            self.model_status_label.configure(text=str(status), fg=AMBER)
        elif event_type == "model_pull_complete":
            self.model_busy = False
            self.model_pull_button.configure(state="normal")
            self.model_progress.configure(value=100)
            self.model_status_label.configure(
                text=f"اكتمل تنزيل {event['model']}; اختر «استخدام المحدد» لتفعيله.",
                fg=GREEN,
            )
            self._refresh_models()
        elif event_type == "model_pull_error":
            self.model_busy = False
            self.model_pull_button.configure(state="normal")
            self.model_status_label.configure(text=event["message"], fg=RED)
        elif event_type == "command_answer":
            self.command_busy = False
            self.command_send_button.configure(state="normal")
            question = event.get("question", "")
            answer = event.get("answer", "لم يصل رد.")
            self.question_history = (
                self.question_history
                + [
                    {"speaker": "user", "text": question},
                    {"speaker": "assistant", "text": answer},
                ]
            )[-6:]
            self._append_command_message("NEXUS", answer)
        elif event_type == "command_error":
            self.command_busy = False
            self.command_send_button.configure(state="normal")
            self._append_command_message(
                "NEXUS",
                f"تعذر الحصول على الإجابة: {event.get('message', 'خطأ غير معروف')}",
                "error",
            )
        elif event_type == "web_search_results":
            self._show_web_results(event["results"])
            if event.get("analyzing"):
                self.web_status_label.configure(
                    text="اكتمل البحث؛ يجري تحليل المقتطفات على Ollama المحلي…",
                    fg=AMBER,
                )
            elif event.get("analysis_skipped"):
                self._finish_web_search(
                    "اكتمل البحث؛ Ollama غير متاح، لذا لم يُجرَ تحليل محلي.",
                    AMBER,
                )
            else:
                self._finish_web_search("اكتمل البحث.", GREEN)
        elif event_type == "web_analysis_answer":
            self.web_analysis_text.configure(state="normal")
            self.web_analysis_text.delete("1.0", "end")
            self.web_analysis_text.insert("end", event["analysis"])
            self.web_analysis_text.configure(state="disabled")
            self._finish_web_search("اكتمل البحث والتحليل المحلي.", GREEN)
        elif event_type == "web_analysis_error":
            self.web_analysis_text.configure(state="normal")
            self.web_analysis_text.delete("1.0", "end")
            self.web_analysis_text.insert(
                "end", f"تعذر تحليل النتائج محليًا: {event['message']}"
            )
            self.web_analysis_text.configure(state="disabled")
            self._finish_web_search(
                "ظهرت نتائج البحث، لكن التحليل المحلي تعذّر. راجع الرسالة أدناه.",
                AMBER,
            )
        elif event_type == "web_search_error":
            self._finish_web_search(
                f"تعذر البحث: {event['message']}",
                RED,
            )
        elif event_type == "integration_status":
            for source in event.get("sources", []):
                self._add_event(f"تم تفعيل مصدر أمني للقراءة فقط: {source}", "success")
        elif event_type == "stopped":
            self._set_monitor_stopped()

    def _update_snapshot(self, snapshot: Dict[str, Any], summary: Dict[str, Any]) -> None:
        self.scan_count += 1
        self.latest_snapshot = snapshot
        self.latest_summary = summary
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
        self.recent_alerts = (self.recent_alerts + alerts)[-20:]
        security_events = event.get("security_events", [])
        if isinstance(security_events, list):
            self.recent_security_events = (
                self.recent_security_events + security_events
            )[-20:]
        self.alert_count += len(alerts)
        self.metric_values["alerts"].configure(text=str(self.alert_count))
        self._set_recommendation(isolation_recommendation(event))
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

    def _set_recommendation(self, text: str) -> None:
        self.recommendation_text.configure(state="normal")
        self.recommendation_text.delete("1.0", "end")
        self.recommendation_text.insert("end", f"اقتراح مراجعة/عزل (استشاري):\n{text}")
        self.recommendation_text.configure(state="disabled")

    def _append_command_message(self, speaker: str, text: str, tag: str = "assistant") -> None:
        self.command_text.configure(state="normal")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.command_text.insert("end", f"{timestamp}  {speaker}\n", tag)
        self.command_text.insert("end", f"{text}\n\n", tag)
        line_count = int(self.command_text.index("end-1c").split(".")[0])
        if line_count > 240:
            self.command_text.delete("1.0", f"{line_count - 240}.0")
        self.command_text.see("end")
        self.command_text.configure(state="disabled")

    def submit_command(self, _event: Optional[Any] = None) -> str:
        question = self.command_entry.get().strip()
        if not question or self.command_busy:
            return "break"
        self.command_entry.delete(0, "end")
        self._append_command_message("أنت", question, "user")

        command = parse_command(question)
        if command is not None:
            self._run_safe_command(command)
            return "break"
        if len(question) > 500:
            self._append_command_message(
                "NEXUS",
                "الأسئلة الحرة محدودة بـ500 حرف للمحافظة على استجابة التطبيق.",
                "error",
            )
            return "break"
        if not self.ollama_available:
            self._append_command_message(
                "NEXUS",
                "Ollama غير متاح الآن. الأوامر المحددة تعمل دون Ollama؛ "
                "شغّله محليًا لطرح أسئلة حرة.",
                "error",
            )
            return "break"

        context = {
            "monitoring": self.monitor_active,
            "scan_count": self.scan_count,
            "summary": self.latest_summary,
            "sample_connections": self.latest_summary.get("sample_connections", []),
            "recent_alerts": self.recent_alerts,
        }
        history = list(self.question_history)
        self.command_busy = True
        self.command_send_button.configure(state="disabled")
        self._append_command_message("NEXUS", "جارٍ إعداد إجابة من Ollama المحلي…")
        threading.Thread(
            target=self._question_worker,
            args=(question, context, history),
            name="local-command-question",
            daemon=True,
        ).start()
        return "break"

    def _run_safe_command(self, command: str) -> None:
        if command == "help":
            response = (
                "الأوامر المتاحة: مساعدة، الحالة، التنبيهات، الاتصالات، التوصيات، "
                "ابدأ، أوقف، التقارير. أي نص آخر يُعامل كسؤال إلى Ollama عند توفره؛ "
                "لا تُنفذ أوامر shell أو أوامر نظام."
            )
        elif command == "status":
            if not self.latest_snapshot:
                response = "لم يكتمل فحص بعد. استخدم «ابدأ» لبدء المراقبة يدويًا."
            else:
                response = (
                    f"حالة المراقبة: {'تعمل' if self.monitor_active else 'متوقفة'}؛ "
                    f"عدد الفحوص: {self.scan_count}؛ "
                    f"الاتصالات النشطة: {self.latest_summary.get('active_connections', 0)}؛ "
                    f"الاتصالات البعيدة: {self.latest_summary.get('total_remote_connections', 0)}؛ "
                    f"التنبيهات: {self.alert_count}."
                )
        elif command == "alerts":
            response = (
                "\n".join(
                    f"- {alert.get('rule', 'unknown')}: {alert.get('detail', '')[:300]}"
                    for alert in self.recent_alerts[-5:]
                )
                or "لا توجد تنبيهات حديثة في هذه الجلسة."
            )
        elif command == "connections":
            connections = self.latest_summary.get("sample_connections", [])[:5]
            response = (
                "\n".join(
                    f"- {item.get('process', 'unknown')}: "
                    f"{item.get('remote_ip', '')}:{item.get('remote_port', '')} "
                    f"({item.get('status', 'UNKNOWN')})"
                    for item in connections
                )
                or "لا توجد عينة اتصالات بعد؛ ابدأ المراقبة أولًا."
            )
        elif command == "recommendations":
            event = {
                "alerts": self.recent_alerts,
                "security_events": self.recent_security_events,
            }
            response = isolation_recommendation(event)
        elif command == "start":
            self.start_monitor()
            response = "بدأت المراقبة." if self.monitor_active else "تعذر بدء المراقبة؛ راجع الإعدادات."
        elif command == "stop":
            if self.monitor_active:
                self.stop_monitor()
                response = "طُلب إيقاف المراقبة بعد الفحص الحالي."
            else:
                response = "المراقبة متوقفة بالفعل."
        else:
            opened = self.open_reports()
            response = (
                "تم فتح مجلد التقارير المحلي."
                if opened
                else "تعذر فتح مجلد التقارير؛ راجع رسالة الخطأ."
            )
        self._append_command_message("NEXUS", response)

    def _question_worker(
        self,
        question: str,
        context: Dict[str, Any],
        history: List[Dict[str, str]],
    ) -> None:
        try:
            answer = agent.ask_local_question(question, context, history)
            self.events.put(
                {"type": "command_answer", "question": question, "answer": answer}
            )
        except Exception as exc:
            agent.logger.exception("Local dashboard question failed")
            self.events.put(
                {"type": "command_error", "message": f"{type(exc).__name__}: {exc}"}
            )

    def submit_web_search(self, _event: Optional[Any] = None) -> str:
        query = self.web_search_entry.get().strip()
        if not query or self.web_busy:
            return "break"
        if len(query) > MAX_QUERY_CHARS:
            self.web_status_label.configure(
                text=f"عبارة البحث محدودة بـ{MAX_QUERY_CHARS} حرفًا.",
                fg=RED,
            )
            return "break"

        analyze_locally = self.web_analysis_var.get()
        ollama_available = self.ollama_available
        self.web_busy = True
        self.web_search_button.configure(state="disabled")
        self.web_status_label.configure(text="جارٍ البحث في الويب…", fg=AMBER)
        self.web_analysis_text.configure(state="normal")
        self.web_analysis_text.delete("1.0", "end")
        self.web_analysis_text.configure(state="disabled")
        threading.Thread(
            target=self._web_research_worker,
            args=(query, analyze_locally, ollama_available),
            name="web-search-and-local-analysis",
            daemon=True,
        ).start()
        return "break"

    def _web_research_worker(
        self, query: str, analysis_requested: bool, ollama_available: bool
    ) -> None:
        analyze_locally = analysis_requested and ollama_available
        try:
            results = search_web(query)
        except Exception as exc:
            agent.logger.exception("Public web search failed")
            self.events.put(
                {"type": "web_search_error", "message": f"{type(exc).__name__}: {exc}"}
            )
            return

        self.events.put(
            {
                "type": "web_search_results",
                "results": results,
                "analyzing": analyze_locally,
                "analysis_skipped": analysis_requested and not ollama_available,
            }
        )
        if not analyze_locally:
            return
        try:
            analysis = agent.analyze_web_search_locally(query, results)
            self.events.put({"type": "web_analysis_answer", "analysis": analysis})
        except Exception as exc:
            agent.logger.exception("Local analysis of web search results failed")
            self.events.put(
                {"type": "web_analysis_error", "message": f"{type(exc).__name__}: {exc}"}
            )

    def _show_web_results(self, results: List[Dict[str, str]]) -> None:
        self.web_results_text.configure(state="normal")
        self.web_results_text.delete("1.0", "end")
        for index, result in enumerate(results, start=1):
            self.web_results_text.insert("end", f"{index}. {result['title']}\n")
            if result.get("snippet"):
                self.web_results_text.insert("end", f"{result['snippet']}\n")
            tag = f"web_link_{index}"
            self.web_results_text.insert("end", f"↗ {result['url']}\n\n", tag)
            self.web_results_text.tag_configure(tag, foreground=CYAN, underline=True)
            self.web_results_text.tag_bind(
                tag,
                "<Button-1>",
                lambda _event, url=result["url"]: self._open_web_result(url),
            )
        self.web_results_text.configure(state="disabled")

    def _open_web_result(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            self._add_event("رابط نتيجة البحث غير صالح؛ لم يتم فتحه.", "error")
            return
        if not webbrowser.open_new_tab(url):
            self._add_event("تعذر فتح رابط البحث في المتصفح الافتراضي.", "error")

    def _finish_web_search(self, message: str, color: str) -> None:
        self.web_busy = False
        self.web_search_button.configure(state="normal")
        self.web_status_label.configure(text=message, fg=color)

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

    def _refresh_models(self) -> None:
        threading.Thread(
            target=self._list_models_worker,
            name="ollama-model-list",
            daemon=True,
        ).start()

    def _list_models_worker(self) -> None:
        try:
            models = installed_models(agent.OLLAMA_URL)
            self.events.put({"type": "model_list", "models": models})
        except Exception as exc:
            agent.logger.exception("Could not list locally installed Ollama models")
            self.events.put(
                {
                    "type": "model_list_error",
                    "message": f"تعذرت إدارة النماذج: {type(exc).__name__}: {exc}",
                }
            )

    def _activate_selected_model(self) -> None:
        model = self.model_var.get()
        if model not in SUPPORTED_MODELS:
            self.model_status_label.configure(text="اختر نموذجًا من القائمة.", fg=RED)
            return
        if model not in self.available_models:
            self.model_status_label.configure(
                text="النموذج غير مثبت؛ نزّله أولًا من Ollama المحلي.", fg=AMBER
            )
            return
        try:
            persist_model_selection(model, agent.APP_DIR / ".env")
        except RuntimeError as exc:
            agent.logger.exception("Could not persist the selected local AI model")
            self.model_status_label.configure(text=str(exc), fg=RED)
            return
        agent.AI_MODEL = model
        self.model_status_label.configure(text=f"النموذج النشط: {model}", fg=GREEN)
        threading.Thread(
            target=self._probe_ollama,
            name="ollama-status-check",
            daemon=True,
        ).start()

    def _on_model_choice(self, _event: Optional[Any] = None) -> None:
        model = self.model_var.get()
        if model in self.available_models:
            self.model_status_label.configure(text=f"النموذج مثبت: {model}", fg=GREEN)
        else:
            self.model_status_label.configure(text=f"{model} غير مثبت.", fg=AMBER)

    def _start_model_download(self) -> None:
        model = self.model_var.get()
        if model not in SUPPORTED_MODELS:
            self.model_status_label.configure(text="اختر نموذجًا من القائمة.", fg=RED)
            return
        if self.model_busy:
            return
        if model in self.available_models:
            self.model_status_label.configure(text=f"{model} مثبت بالفعل.", fg=GREEN)
            return
        self.model_busy = True
        self.model_pull_button.configure(state="disabled")
        self.model_progress.configure(value=0)
        self.model_status_label.configure(
            text="جارٍ التحقق من حجم النموذج الرسمي قبل التنزيل…", fg=AMBER
        )
        threading.Thread(
            target=self._model_download_worker,
            args=(model,),
            name="ollama-model-download",
            daemon=True,
        ).start()

    def _model_download_worker(self, model: str) -> None:
        last_progress = None

        def report_progress(update: Dict[str, Any]) -> None:
            nonlocal last_progress
            completed = update.get("completed")
            total = update.get("total")
            percent = (
                min(100, int(completed * 100 / total))
                if type(completed) is int and type(total) is int and total > 0
                else None
            )
            state = (update.get("status"), update.get("digest"), percent)
            if state != last_progress:
                self.events.put({"type": "model_pull_progress", "update": update})
                last_progress = state

        try:
            pull_model(
                agent.OLLAMA_URL,
                model,
                report_progress,
            )
            self.events.put({"type": "model_pull_complete", "model": model})
        except Exception as exc:
            agent.logger.exception("Optional Ollama model download failed")
            self.events.put(
                {
                    "type": "model_pull_error",
                    "message": f"تعذر تنزيل النموذج: {type(exc).__name__}: {exc}",
                }
            )

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
            available = False
            text = "OLLAMA  •  غير متصل"
            color = RED
        self.events.put(
            {"type": "ollama_status", "text": text, "color": color, "available": available}
        )

    def open_reports(self) -> bool:
        try:
            agent.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            opened = webbrowser.open(agent.REPORTS_DIR.as_uri())
        except (OSError, webbrowser.Error) as exc:
            messagebox.showerror("تعذر فتح التقارير", str(exc))
            return False
        if not opened:
            messagebox.showerror("تعذر فتح التقارير", str(agent.REPORTS_DIR))
        return opened

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
