#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebCat Downloader — вибіркове завантаження з веб-каталогів (Apache/nginx autoindex).

Дерево з трипозиційними галочками:
    ☐ — не вибрано
    ☑ — вибрано
    ◪ — вибрано частково (частина вкладених)

Тільки стандартна бібліотека Python 3.8+. Запуск:  python webcat_downloader.py
"""

import os
import re
import ssl
import queue
import base64
import socket
import pathlib
import threading
import webbrowser
import html as html_lib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, unquote, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

UA = "Mozilla/5.0 (WebCatDownloader/1.0)"
TIMEOUT = 30

# --------------------------------------------------------------------------
#  TLS: контекст перевірки сертифікатів (керується з UI)
# --------------------------------------------------------------------------
try:
    import certifi
    _CERTIFI = certifi.where()
except Exception:
    _CERTIFI = None


def build_ctx(ca_file=None, verify=True):
    """Свій CA-bundle → certifi → системне сховище ОС; або зовсім без перевірки."""
    if not verify:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    if _CERTIFI:
        return ssl.create_default_context(cafile=_CERTIFI)
    return ssl.create_default_context()


# активний контекст; App._apply_tls() його підмінює
SSL_CTX = build_ctx()


def decode_cert(der):
    """DER-байти сертифіката → dict (subject/issuer/notAfter/…). Лише stdlib."""
    import tempfile
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

OFF, ON, PART = 0, 1, 2
GLYPH = {OFF: "☐", ON: "☑", PART: "◪"}

# посилання, які треба ігнорувати в autoindex
SKIP_RE = re.compile(r"^(\?|#|mailto:|javascript:)", re.I)
DATE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?"          # 2026-06-01 18:42
    r"|\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}(?::\d{2})?"      # 01-Jun-2026 18:42
    r"|\d{2}/[A-Za-z]{3}/\d{4}\s+\d{2}:\d{2})"                # 01/Jun/2026 18:42
)
SIZE_RE = re.compile(r"(?<![\w.])(\d+(?:[.,]\d+)?)\s?([KMGT])?(?:B|iB)?(?![\w.])", re.I)


# --------------------------------------------------------------------------
#  Парсинг autoindex-сторінки
# --------------------------------------------------------------------------
class IndexParser(HTMLParser):
    """Витягує (href, текст, зміщення_кінця_тега) у порядку появи."""

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._href = None
        self._buf = []
        # таблиця зміщень початку рядків — щоб getpos() перевести в offset
        self._lines = [0]
        for line in html.splitlines(keepends=True):
            self._lines.append(self._lines[-1] + len(line))

    def _offset(self):
        row, col = self.getpos()
        return self._lines[min(row - 1, len(self._lines) - 1)] + col

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._buf = []

    def handle_data(self, data):
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip(), self._offset()))
            self._href = None
            self._buf = []


def human_to_bytes(s):
    """'1.4M' -> 1468006. Повертає 0, якщо не розпізнано."""
    if not s:
        return 0
    s = s.strip().replace(",", ".").replace(" ", "")
    m = re.match(r"^(\d+(?:\.\d+)?)([KMGT]?)$", s, re.I)
    if not m:
        return 0
    num = float(m.group(1))
    mult = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    return int(num * mult[m.group(2).upper()])


def bytes_to_human(n):
    if n <= 0:
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def fetch(url, auth=None, range_from=None):
    headers = {"User-Agent": UA, "Accept": "*/*"}
    if auth:
        token = base64.b64encode(auth.encode("utf-8")).decode("ascii")
        headers["Authorization"] = "Basic " + token
    if range_from:
        headers["Range"] = f"bytes={range_from}-"
    return urlopen(Request(url, headers=headers), timeout=TIMEOUT, context=SSL_CTX)


def list_directory(url, auth=None, stats=None):
    """Повертає список dict(name, url, is_dir, size, date) для autoindex-сторінки.
    stats, якщо переданий dict, накопичує лічильники відфільтрованих посилань:
    "external" (інший домен) і "out_of_scope" (той самий сайт, але поза текою)."""
    if not url.endswith("/"):
        url += "/"
    with fetch(url, auth) as resp:
        raw = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
    html = raw.decode(charset, errors="replace")

    parser = IndexParser(html)
    parser.feed(html)
    links = parser.links
    ends = [lk[2] for lk in links] + [len(html)]

    base_path = urlparse(url).path
    items, seen = [], set()

    for i, (href, text, pos) in enumerate(links):
        if not href or SKIP_RE.match(href):
            continue
        full = urljoin(url, href)
        if urlparse(full).netloc != urlparse(url).netloc:
            if stats is not None:
                stats["external"] = stats.get("external", 0) + 1
            continue
        path = urlparse(full).path
        # батьківський каталог або сам каталог
        if not path.startswith(base_path) or path == base_path:
            if stats is not None and path != base_path:
                stats["out_of_scope"] = stats.get("out_of_scope", 0) + 1
            continue
        if full in seen:
            continue
        seen.add(full)

        is_dir = path.endswith("/")
        name = unquote(path.rstrip("/").split("/")[-1])
        if not name or name in ("..", "."):
            continue

        # хвіст = все між кінцем цього <a> і початком наступного
        tail = re.sub(r"<[^>]+>", " ", html[pos:ends[i + 1]])[:250]
        size, date = 0, ""
        dm = DATE_RE.search(tail)
        if dm:
            date = re.sub(r"\s+", " ", dm.group(1))
            tail = tail[dm.end():]
        if not is_dir:
            for sm in SIZE_RE.finditer(tail):
                token = sm.group(1) + (sm.group(2) or "")
                val = human_to_bytes(token)
                if val:
                    size = val
                    break

        items.append({"name": name, "url": full, "is_dir": is_dir,
                      "size": size, "date": date,
                      "page": (not is_dir) and is_page_url(full)})

    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return items


_STRONG_PAGE_EXTS = {".html", ".htm", ".shtml", ".xhtml", ".php", ".asp", ".aspx", ".jsp"}


def is_page_url(url):
    """Евристика: чи схоже посилання на звичайну HTML-сторінку (не на файл-завантаження)."""
    ext = os.path.splitext(urlparse(url).path)[1].lower()
    return ext in _STRONG_PAGE_EXTS or ext == ""


def looks_like_file_url(url):
    """Чи вказує URL на конкретний файл (є розширення), а не на теку."""
    return bool(os.path.splitext(urlparse(url).path)[1])


def base_dir_path(base_url):
    """Шлях ТЕКИ, що містить base_url: якщо base_url — файл (є розширення),
    повертає шлях без імені файлу; якщо це вже тека — як є, з "/" на кінці."""
    p = urlparse(base_url).path
    if os.path.splitext(p)[1]:
        return p.rsplit("/", 1)[0] + "/"
    return p if p.endswith("/") else p + "/"


def list_page_links(url, auth=None, stats=None):
    """Для звичайної (не-autoindex) HTML-сторінки: посилання на інші сторінки/файли
    в межах теки, що її містить. На відміну від list_directory — URL НЕ чіпається,
    і якщо відповідь не HTML, повертає порожній список (не читає тіло даремно).
    stats — те саме, що й у list_directory."""
    with fetch(url, auth) as resp:
        ctype = (resp.headers.get_content_type() or "").lower()
        if ctype and "html" not in ctype:
            return []
        raw = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
    html = raw.decode(charset, errors="replace")

    parser = IndexParser(html)
    parser.feed(html)

    base_dir = url.rsplit("/", 1)[0] + "/"
    base_path = urlparse(base_dir).path
    base_netloc = urlparse(url).netloc
    self_path = urlparse(url).path

    items, seen = [], set()
    for href, text, pos in parser.links:
        if not href or SKIP_RE.match(href):
            continue
        full = urljoin(url, href)
        if urlparse(full).netloc != base_netloc:
            if stats is not None:
                stats["external"] = stats.get("external", 0) + 1
            continue
        path = urlparse(full).path
        if path == self_path:
            continue
        if not path.startswith(base_path):
            if stats is not None:
                stats["out_of_scope"] = stats.get("out_of_scope", 0) + 1
            continue
        if full in seen:
            continue
        seen.add(full)
        is_dir = path.endswith("/")
        name = unquote(path.rstrip("/").split("/")[-1]) or "index"
        items.append({"name": name, "url": full, "is_dir": is_dir,
                      "size": 0, "date": "",
                      "page": (not is_dir) and is_page_url(full)})
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return items


# --------------------------------------------------------------------------
#  Дзеркалення HTML-сторінки з ресурсами (img/css/js) — для перегляду офлайн
# --------------------------------------------------------------------------
_ASSET_ATTRS = {
    "img": ("src",), "script": ("src",), "source": ("src",),
    "link": ("href",), "embed": ("src",),
    "video": ("src", "poster"), "audio": ("src",),
}


class PageAssetParser(HTMLParser):
    """Знаходить теги з ресурсами разом з офсетом і СИРИМ (незміненим) текстом тега —
    щоб потім точково замінити лише значення атрибута, не чіпаючи решту документа."""

    def __init__(self, html):
        super().__init__(convert_charrefs=False)
        self.tags = []
        self._lines = [0]
        for line in html.splitlines(keepends=True):
            self._lines.append(self._lines[-1] + len(line))

    def _offset(self):
        row, col = self.getpos()
        return self._lines[min(row - 1, len(self._lines) - 1)] + col

    def handle_starttag(self, tag, attrs):
        raw = self.get_starttag_text() or ""
        start = self._offset()
        self.tags.append((start, start + len(raw), tag.lower(), dict(attrs), raw))


def _replace_attr_value(raw_tag, attr, old_val, new_val):
    """Замінює значення атрибута в сирому тексті ОДНОГО тега: квотоване або
    (типово для старих сторінок) неквотоване attr=value без лапок."""
    for q in ('"', "'"):
        replaced = raw_tag.replace(f"{attr}={q}{old_val}{q}", f"{attr}={q}{new_val}{q}", 1)
        if replaced != raw_tag:
            return replaced
    return re.sub(re.escape(f"{attr}={old_val}") + r"(?=[\s/>])",
                  lambda m: f"{attr}={new_val}", raw_tag, count=1)


# --------------------------------------------------------------------------
#  Локальний HTML-навігатор для вже скачаної папки (переходи в браузері,
#  а не в провіднику). Усі посилання відносні — тека переноситься куди завгодно.
# --------------------------------------------------------------------------
_NAV_NAME = "_webcat_index.html"
_NAV_TEMPLATE = """<!DOCTYPE html>
<!-- webcat-navigator: автоматично згенеровано, можна перестворити в програмі -->
<html><head><meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: "Segoe UI", Arial, sans-serif; margin: 24px; color: #222; }}
h1 {{ font-size: 15px; font-weight: normal; margin-bottom: 18px; }}
table {{ border-collapse: collapse; width: 100%; max-width: 900px; }}
td {{ padding: 4px 10px; border-bottom: 1px solid #eee; font-size: 14px; }}
td:first-child {{ width: 22px; }}
td:last-child {{ text-align: right; color: #666; white-space: nowrap; }}
a {{ text-decoration: none; color: #1a4d8f; }}
a:hover {{ text-decoration: underline; }}
</style></head>
<body>
<h1>{crumbs}</h1>
<table>
{rows}
</table>
</body></html>
"""


def _breadcrumb_html(crumbs):
    if not crumbs:
        return "<b>[корінь]</b>"
    depth = len(crumbs)
    parts = [f'<a href="{"../" * depth}{_NAV_NAME}">[корінь]</a>']
    for i, name in enumerate(crumbs):
        esc = html_lib.escape(name)
        if i == depth - 1:
            parts.append(f"<b>{esc}</b>")
        else:
            up = depth - i - 1
            parts.append(f'<a href="{"../" * up}{_NAV_NAME}">{esc}</a>')
    return " / ".join(parts)


def build_local_navigator(root_dir, progress_cb=None):
    """Створює в КОЖНІЙ підпапці дерева файл-покажчик (_webcat_index.html) з
    переходами лише по відносних посиланнях — тому вся структура лишається
    робочою, якщо потім перенести/перейменувати батьківську папку куди завгодно.
    Повертає шлях до кореневого покажчика (звідки почати перегляд у браузері)."""
    root_dir = os.path.abspath(root_dir)

    # розмір кожної підпапки рекурсивно — щоб показати в списку
    dir_size = {}
    for dirpath, dirnames, filenames in os.walk(root_dir, topdown=False):
        total = sum(os.path.getsize(os.path.join(dirpath, f)) for f in filenames
                    if f != _NAV_NAME and not f.endswith(".part"))
        for d in dirnames:
            total += dir_size.get(os.path.join(dirpath, d), 0)
        dir_size[dirpath] = total

    made = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames.sort(key=str.lower)
        filenames = sorted((f for f in filenames
                            if f != _NAV_NAME and not f.endswith(".part")),
                           key=str.lower)

        rel_from_root = os.path.relpath(dirpath, root_dir)
        crumbs = [] if rel_from_root == "." else rel_from_root.replace(os.sep, "/").split("/")

        rows = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            href = quote(d, safe="") + "/" + _NAV_NAME
            rows.append(f'<tr><td>📁</td><td><a href="{href}">{html_lib.escape(d)}/</a></td>'
                       f'<td>{bytes_to_human(dir_size.get(full, 0))}</td></tr>')
        for f in filenames:
            full = os.path.join(dirpath, f)
            href = quote(f, safe="")
            rows.append(f'<tr><td>📄</td><td><a href="{href}">{html_lib.escape(f)}</a></td>'
                       f'<td>{bytes_to_human(os.path.getsize(full))}</td></tr>')
        if not rows:
            rows.append("<tr><td></td><td><i>(порожньо)</i></td><td></td></tr>")

        title = "/".join(crumbs) or os.path.basename(root_dir) or "/"
        out = _NAV_TEMPLATE.format(title=html_lib.escape(title),
                                   crumbs=_breadcrumb_html(crumbs),
                                   rows="\n".join(rows))
        with open(os.path.join(dirpath, _NAV_NAME), "w", encoding="utf-8") as f:
            f.write(out)
        made += 1
        if progress_cb:
            progress_cb(made)

    return os.path.join(root_dir, _NAV_NAME)


def _asset_local_name(url, used_names):
    name = unquote(urlparse(url).path.rsplit("/", 1)[-1]) or "asset"
    name = re.sub(r'[<>:"|?*]', "_", name)
    base, ext = os.path.splitext(name)
    candidate, i = name, 1
    while candidate.lower() in used_names:
        i += 1
        candidate = f"{base}_{i}{ext}"
    used_names.add(candidate.lower())
    return candidate


# --------------------------------------------------------------------------
#  Головне вікно
# --------------------------------------------------------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WebCat Downloader — вибіркове завантаження веб-каталогів")
        self.geometry("1050x680")
        self.minsize(820, 520)

        self.nodes = {}            # iid -> dict
        self.seen_urls = {}        # url -> iid: щоб той самий ресурс не дублювався в дереві
        self.msgq = queue.Queue()  # повідомлення з робочих потоків
        self.stop_evt = threading.Event()
        self.busy = False
        self.dl_report = []        # записи для підсумкового звіту про останнє завантаження

        self._build_ui()
        # Ctrl+C/V/X/A незалежно від розкладки клавіатури
        self.bind_class("TEntry", "<Control-KeyPress>", self._on_ctrl_key, add="+")
        self.after(100, self._pump)

    # ---------------------------------------------------------------- UI
    def _build_ui(self):
        pad = {"padx": 6, "pady": 4}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="URL каталогу:").grid(row=0, column=0, sticky="w")
        self.url_var = tk.StringVar(value="https://")
        e = ttk.Entry(top, textvariable=self.url_var)
        e.grid(row=0, column=1, sticky="ew", padx=4)
        e.bind("<Return>", lambda _e: self.load_root())
        self._attach_entry_menu(e)

        ttk.Button(top, text="Відкрити", command=self.load_root).grid(row=0, column=2)
        ttk.Button(top, text="Сканувати все ↓", command=self.scan_all).grid(row=0, column=3, padx=4)
        ttk.Button(top, text="Зберегти сторінку", command=self.save_current_page).grid(row=0, column=4, padx=4)

        ttk.Label(top, text="Логін:").grid(row=1, column=0, sticky="w")
        auth = ttk.Frame(top)
        auth.grid(row=1, column=1, sticky="w", padx=4)
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        ttk.Entry(auth, textvariable=self.user_var, width=18).pack(side="left")
        ttk.Label(auth, text="  Пароль:").pack(side="left")
        ttk.Entry(auth, textvariable=self.pass_var, width=18, show="•").pack(side="left")
        ttk.Label(auth, text="  (лише якщо каталог під Basic-auth)").pack(side="left")

        # --- TLS / сертифікати
        ttk.Label(top, text="TLS:").grid(row=2, column=0, sticky="w")
        tls = ttk.Frame(top)
        tls.grid(row=2, column=1, columnspan=3, sticky="ew", padx=4, pady=(2, 0))
        self.no_verify_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(tls, text="Без перевірки сертифіката",
                        variable=self.no_verify_var,
                        command=self._apply_tls).pack(side="left")
        ttk.Label(tls, text="   Свій CA-bundle:").pack(side="left")
        self.ca_var = tk.StringVar()
        ttk.Entry(tls, textvariable=self.ca_var, width=30).pack(side="left", padx=2)
        ttk.Button(tls, text="…", width=3, command=self._pick_ca).pack(side="left")
        ttk.Button(tls, text="Тест з'єднання",
                   command=self.test_connection).pack(side="left", padx=6)
        ttk.Label(tls, text=("[certifi]" if _CERTIFI else "[сховище ОС]"),
                  foreground="#666").pack(side="left")

        top.columnconfigure(1, weight=1)

        # --- панель вибору
        bar = ttk.Frame(self)
        bar.pack(fill="x", **pad)
        ttk.Button(bar, text="Вибрати все", command=lambda: self.set_all(ON)).pack(side="left")
        ttk.Button(bar, text="Зняти все", command=lambda: self.set_all(OFF)).pack(side="left", padx=4)
        ttk.Button(bar, text="Інвертувати", command=self.invert).pack(side="left")

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(bar, text="Лише сторінки 🔗", command=self.select_pages_only).pack(side="left")
        ttk.Button(bar, text="Лише файли", command=self.select_files_only).pack(side="left", padx=4)

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Label(bar, text="Маска:").pack(side="left")
        self.mask_var = tk.StringVar(value="*.pdf *.epub")
        ttk.Entry(bar, textvariable=self.mask_var, width=24).pack(side="left", padx=4)
        ttk.Button(bar, text="Вибрати за маскою", command=self.select_by_mask).pack(side="left")

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(bar, text="Експорт списку URL", command=self.export_list).pack(side="left")
        ttk.Button(bar, text="rclone-фільтр…", command=self.export_rclone_filter).pack(side="left", padx=4)
        ttk.Button(bar, text="Навігатор для папки…",
                  command=self.build_navigator_dialog).pack(side="left", padx=4)

        self.selinfo_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.selinfo_var,
                  foreground="#1c6fe0").pack(side="right", padx=6)

        # --- дерево
        wrap = ttk.Frame(self)
        wrap.pack(fill="both", expand=True, **pad)

        self.tree = ttk.Treeview(wrap, columns=("sel", "size", "date"),
                                 selectmode="extended")
        self.tree.heading("#0", text="Назва")
        self.tree.heading("sel", text="✓")
        self.tree.heading("size", text="Розмір")
        self.tree.heading("date", text="Змінено")
        self.tree.column("#0", width=560, stretch=True)
        self.tree.column("sel", width=40, anchor="center", stretch=False)
        self.tree.column("size", width=110, anchor="e", stretch=False)
        self.tree.column("date", width=150, anchor="center", stretch=False)

        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        style = ttk.Style(self)
        style.configure("Treeview", rowheight=24)
        style.map("Treeview",
                  background=[("selected", "#1c6fe0")],
                  foreground=[("selected", "white")])
        self.tree.tag_configure("dir", foreground="#1a4d8f")
        self.tree.tag_configure("page", foreground="#2f7a3d")
        self.tree.bind("<Button-1>", self.on_click)
        self.tree.bind("<space>", self.on_space)
        self.tree.bind("<<TreeviewOpen>>", self.on_expand)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Control-KeyPress>", self._on_tree_ctrl_key)
        self._build_tree_menu()

        # --- низ
        bot = ttk.Frame(self)
        bot.pack(fill="x", **pad)

        ttk.Label(bot, text="Зберігати у:").grid(row=0, column=0, sticky="w")
        self.dir_var = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Downloads"))
        ttk.Entry(bot, textvariable=self.dir_var).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(bot, text="…", width=3, command=self.pick_dir).grid(row=0, column=2)

        ttk.Label(bot, text="Потоків:").grid(row=0, column=3, padx=(10, 2))
        self.threads_var = tk.IntVar(value=3)
        ttk.Spinbox(bot, from_=1, to=8, width=4, textvariable=self.threads_var).grid(row=0, column=4)

        self.flat_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bot, text="Без підпапок", variable=self.flat_var).grid(row=0, column=5, padx=8)

        self.page_assets_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bot, text="HTML-сторінки — зберігати з ресурсами "
                                  "(зображення/CSS) для перегляду офлайн",
                       variable=self.page_assets_var).grid(
            row=1, column=0, columnspan=6, sticky="w", pady=(4, 0))

        self.dl_btn = ttk.Button(bot, text="⬇ Завантажити вибране", command=self.start_download)
        self.dl_btn.grid(row=0, column=6, padx=4)
        self.stop_btn = ttk.Button(bot, text="Стоп", command=self.stop, state="disabled")
        self.stop_btn.grid(row=0, column=7)
        bot.columnconfigure(1, weight=1)

        self.prog = ttk.Progressbar(self, mode="determinate")
        self.prog.pack(fill="x", padx=6)

        self.status = tk.StringVar(value="Введіть URL каталогу і натисніть «Відкрити».")
        ttk.Label(self, textvariable=self.status, anchor="w",
                  relief="sunken").pack(fill="x", side="bottom")

        self.log = tk.Text(self, height=7, wrap="none", font=("Consolas", 9))
        self.log.pack(fill="x", padx=6, pady=(0, 4))
        self._attach_log_menu(self.log)

    # ------------------------------------------------- буфер обміну
    _CLIP_KC = {86: "<<Paste>>", 67: "<<Copy>>", 88: "<<Cut>>", 65: "all"}
    _CLIP_KS = {
        "v": "<<Paste>>", "cyrillic_em": "<<Paste>>",
        "c": "<<Copy>>", "cyrillic_es": "<<Copy>>",
        "x": "<<Cut>>", "cyrillic_che": "<<Cut>>",
        "a": "all", "cyrillic_ef": "all",
    }

    def _on_ctrl_key(self, event):
        """Ctrl+C/V/X/A незалежно від розкладки (кирилиця ламає штатні прив'язки)."""
        if not (event.state & 0x0004):          # немає Control
            return
        act = self._CLIP_KC.get(event.keycode) or self._CLIP_KS.get(event.keysym.lower())
        if not act:
            return
        w = event.widget
        try:
            if act == "all":
                w.select_range(0, "end")
                w.icursor("end")
            else:
                w.event_generate(act)
        except tk.TclError:
            pass
        return "break"

    def _text_ctrl_key(self, event, widget):
        """Те саме для tk.Text: Ctrl+C — копіювати виділене, Ctrl+A — виділити все."""
        if not (event.state & 0x0004):
            return
        act = self._CLIP_KC.get(event.keycode) or self._CLIP_KS.get(event.keysym.lower())
        if act == "<<Copy>>":
            widget.event_generate("<<Copy>>")
            return "break"
        if act == "all":
            widget.tag_add("sel", "1.0", "end")
            return "break"

    def _copy_text_widget(self, widget):
        self.clipboard_clear()
        self.clipboard_append(widget.get("1.0", "end-1c"))
        self.update_idletasks()

    def _attach_log_menu(self, widget):
        """Контекстне меню для журналу знизу: копіювати / виділити все / очистити."""
        widget.bind("<Control-KeyPress>", lambda e: self._text_ctrl_key(e, widget))
        m = tk.Menu(widget, tearoff=0)
        m.add_command(label="Копіювати виділене", command=lambda: widget.event_generate("<<Copy>>"))
        m.add_command(label="Виділити все", command=lambda: widget.tag_add("sel", "1.0", "end"))
        m.add_command(label="Копіювати весь журнал", command=lambda: self._copy_text_widget(widget))
        m.add_separator()
        m.add_command(label="Очистити журнал", command=lambda: widget.delete("1.0", "end"))

        def popup(e):
            try:
                m.tk_popup(e.x_root, e.y_root)
            finally:
                m.grab_release()

        widget.bind("<Button-3>", popup)

    def _attach_entry_menu(self, widget):
        """Контекстне меню (права кнопка) з Вирізати / Копіювати / Вставити."""
        m = tk.Menu(widget, tearoff=0)
        m.add_command(label="Вирізати", command=lambda: widget.event_generate("<<Cut>>"))
        m.add_command(label="Копіювати", command=lambda: widget.event_generate("<<Copy>>"))
        m.add_command(label="Вставити", command=lambda: widget.event_generate("<<Paste>>"))
        m.add_separator()
        m.add_command(label="Виділити все",
                      command=lambda: (widget.select_range(0, "end"), widget.icursor("end")))

        def popup(e):
            widget.focus_set()
            try:
                m.tk_popup(e.x_root, e.y_root)
            finally:
                m.grab_release()

        widget.bind("<Button-3>", popup)

    # ------------------------------------------------- копіювання виділеного
    def _ordered_selection(self):
        """Виділені рядки у порядку дерева (а не в порядку кліків)."""
        sel = set(self.tree.selection())
        out = []

        def walk(node):
            for k in self.tree.get_children(node):
                if k in sel and k in self.nodes:
                    out.append(k)
                walk(k)

        walk("")
        return out

    def _on_tree_select(self, _e=None):
        """Живий підрахунок того, що виділено синім (не галочки)."""
        sel = [self.nodes[i] for i in self.tree.selection() if i in self.nodes]
        if not sel:
            self.selinfo_var.set("")
            return
        files = [n for n in sel if not n["is_dir"]]
        dirs = [n for n in sel if n["is_dir"]]
        total = sum(n["size"] for n in files)
        approx = False
        for n in dirs:
            total += n.get("_dsize", 0)
            if not n.get("_dcomplete"):
                approx = True          # папка не просканована повністю
        parts = []
        if files:
            parts.append(f"файлів: {len(files)}")
        if dirs:
            parts.append(f"папок: {len(dirs)}")
        self.selinfo_var.set(f"Виділено   {'   '.join(parts)}   "
                             f"{'≈ ' if approx else ''}{bytes_to_human(total)}")

    def _copy_selection(self, mode="url"):
        rows = self._ordered_selection()
        if not rows:
            self.status.set("Нічого не виділено (виділяйте рядки по колонці «Назва»).")
            return
        lines = []
        for iid in rows:
            n = self.nodes[iid]
            if mode == "url":
                lines.append(n["url"])
            elif mode == "name":
                lines.append(n["name"] + ("/" if n["is_dir"] else ""))
            else:  # row: назва / розмір / дата — як видно в таблиці
                lines.append("\t".join((
                    n["name"] + ("/" if n["is_dir"] else ""),
                    self.tree.set(iid, "size"),
                    self.tree.set(iid, "date"),
                )))
        text = "\r\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()          # віддати буфер системі
        self.say(f"Скопійовано {len(lines)} рядків у буфер ({mode}).")
        self.status.set(f"У буфері: {len(lines)} рядків — вставляйте у Блокнот (Ctrl+V).")

    def _on_tree_ctrl_key(self, event):
        if not (event.state & 0x0004):                        # немає Control
            return
        if event.keycode == 67 or event.keysym.lower() in ("c", "cyrillic_es"):
            self._copy_selection("url")
            return "break"

    def _build_tree_menu(self):
        m = tk.Menu(self.tree, tearoff=0)
        self._tree_menu = m

        def popup(e):
            row = self.tree.identify_row(e.y)
            if row and row not in self.tree.selection():
                self.tree.selection_set(row)
                self.tree.focus(row)
            m.delete(0, "end")
            node = self.nodes.get(row)
            if node and node["is_dir"]:
                m.add_command(label="Просканувати рекурсивно",
                              command=lambda r=row: self.scan_subtree(r))
                m.add_separator()
            m.add_command(label="Копіювати URL (по рядку)",
                          command=lambda: self._copy_selection("url"))
            m.add_command(label="Копіювати назви",
                          command=lambda: self._copy_selection("name"))
            m.add_command(label="Копіювати рядки: назва / розмір / дата",
                          command=lambda: self._copy_selection("row"))
            if self.tree.selection():
                try:
                    m.tk_popup(e.x_root, e.y_root)
                finally:
                    m.grab_release()

        self.tree.bind("<Button-3>", popup)

    # ------------------------------------------------------- допоміжне
    def auth(self):
        u, p = self.user_var.get().strip(), self.pass_var.get()
        return f"{u}:{p}" if u else None

    # ------------------------------------------------------- TLS
    def _pick_ca(self):
        p = filedialog.askopenfilename(
            title="Файл CA-bundle",
            filetypes=[("Сертифікати", "*.pem *.crt *.cer *.ca-bundle"),
                       ("Усі файли", "*.*")])
        if p:
            self.ca_var.set(p)
            self._apply_tls()

    def _apply_tls(self):
        """Перебудовує глобальний SSL_CTX за станом чекбокса й поля CA-bundle."""
        global SSL_CTX
        ca = self.ca_var.get().strip() or None
        verify = not self.no_verify_var.get()
        try:
            SSL_CTX = build_ctx(ca, verify)
        except Exception as e:
            messagebox.showerror("TLS", f"Не вдалося застосувати налаштування TLS:\n{e}")
            self.no_verify_var.set(False)
            SSL_CTX = build_ctx()
            return
        if not verify:
            self.say("⚠ Перевірку сертифіката ВИМКНЕНО — трафік шифрується, але "
                     "справжність сервера не підтверджується. Не передавайте логін/пароль.")
        elif ca:
            self.say(f"TLS: застосовано власний CA-bundle ({ca}).")

    def test_connection(self):
        url = self.url_var.get().strip()
        if not url.startswith(("http://", "https://")):
            messagebox.showwarning("URL", "Спершу вкажіть URL із http:// або https://")
            return
        self._apply_tls()
        pr = urlparse(url)
        host = pr.hostname
        port = pr.port or (443 if pr.scheme == "https" else 80)
        self.say(f"— Тест з'єднання: {host}:{port} —")
        threading.Thread(target=self._test_worker,
                         args=(url, host, port), daemon=True).start()

    def _test_worker(self, url, host, port):
        # 1) сирий TLS без перевірки — чи живий сервер і який ланцюжок віддає
        if url.startswith("https://"):
            try:
                raw = ssl.create_default_context()
                raw.check_hostname = False
                raw.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), TIMEOUT) as s:
                    with raw.wrap_socket(s, server_hostname=host) as ts:
                        self.msgq.put(("log", f"  TLS OK: {ts.version()} / {ts.cipher()[0]}"))
                        chain = getattr(ts, "get_unverified_chain", lambda: [])() or []
                        for i, der in enumerate(chain):
                            try:
                                info = decode_cert(der if isinstance(der, bytes)
                                                   else der.public_bytes())
                            except Exception:
                                continue
                            cn = dict(x[0] for x in info.get("subject", ())).get("commonName", "?")
                            iss = dict(x[0] for x in info.get("issuer", ())).get("commonName", "?")
                            self.msgq.put(("log", f"    [{i}] {cn}  ←  видав: {iss}"
                                                  f"   до {info.get('notAfter', '?')}"))
            except Exception as e:
                self.msgq.put(("log", f"  ✘ навіть без перевірки не з'єдналось: "
                                      f"{type(e).__name__}: {e}"))
                self.msgq.put(("status", "Тест: сервер недоступний"))
                return
        # 2) реальний запит із поточним контекстом
        try:
            with fetch(url, self.auth()) as resp:
                code = getattr(resp, "status", None) or resp.getcode()
                self.msgq.put(("log", f"  ✔ HTTP {code} — перевірка сертифіката пройдена"))
                self.msgq.put(("status", "Тест з'єднання: OK"))
        except HTTPError as e:
            self.msgq.put(("log", f"  ✔ TLS ок, сервер відповів HTTP {e.code} {e.reason}"))
            self.msgq.put(("status", f"Тест: TLS ок (HTTP {e.code})"))
        except URLError as e:
            reason = getattr(e, "reason", e)
            hint = self._tls_hint(reason) if isinstance(reason, ssl.SSLCertVerificationError) else ""
            self.msgq.put(("log", f"  ✘ {reason}{hint}"))
            self.msgq.put(("status", "Тест: помилка перевірки сертифіката"))
        except Exception as e:
            self.msgq.put(("log", f"  ✘ {type(e).__name__}: {e}"))
            self.msgq.put(("status", "Тест: помилка"))

    @staticmethod
    def _tls_hint(err):
        m = str(err)
        if "self signed" in m or "self-signed" in m:
            return ("\n     → у ланцюжку самопідписаний сертифікат: імовірно проксі або "
                    "антивірус із HTTPS-інспекцією. Експортуйте його корінь і вкажіть у полі CA-bundle.")
        if "expired" in m:
            return ("\n     → прострочений сертифікат у ланцюжку. Спробуйте pip install --upgrade certifi; "
                    "якщо не поможе — тимчасово увімкніть «Без перевірки».")
        if "unable to get local issuer" in m:
            return ("\n     → бракує проміжного/кореневого сертифіката. pip install --upgrade certifi "
                    "або вкажіть свій CA-bundle.")
        if "Hostname mismatch" in m or "doesn't match" in m:
            return "\n     → сертифікат виданий на інше ім'я — перевірте, чи правильний хост у URL."
        return ""

    def say(self, text):
        self.log.insert("end", text + "\n")
        self.log.see("end")

    def _pump(self):
        """Обробка черги повідомлень із робочих потоків."""
        try:
            while True:
                kind, payload = self.msgq.get_nowait()
                if kind == "log":
                    self.say(payload)
                elif kind == "status":
                    self.status.set(payload)
                elif kind == "children":
                    parent, items = payload
                    self._insert_children(parent, items)
                elif kind == "reset_load":
                    node = self.nodes.get(payload)
                    if node:
                        node["loaded"] = False
                        if not self.tree.get_children(payload):
                            self.tree.insert(payload, "end", text="…")
                elif kind == "progress":
                    done, total = payload
                    self.prog["maximum"] = max(total, 1)
                    self.prog["value"] = done
                elif kind == "report":
                    self.dl_report.append(payload)
                elif kind == "report_done":
                    self._show_report()
                elif kind == "done":
                    self.busy = False
                    self.dl_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    self._refresh_all_sizes()
                    self.status.set(payload)
        except queue.Empty:
            pass
        self.after(100, self._pump)

    # ------------------------------------------------------ побудова дерева
    def load_root(self):
        url = self.url_var.get().strip()
        if not url.startswith(("http://", "https://")):
            messagebox.showwarning("URL", "Вкажіть повний URL із http:// або https://")
            return
        # "/" дописуємо лише коли URL схожий на теку (без розширення файлу) —
        # інакше пряме посилання на конкретну сторінку (.../index.html) ламається
        # перетворенням на неіснуючий шлях .../index.html/
        if not url.endswith("/") and not looks_like_file_url(url):
            url += "/"
            self.url_var.set(url)
        self._apply_tls()
        self.tree.delete(*self.tree.get_children())
        self.nodes.clear()
        self.seen_urls.clear()
        self.status.set("Читаю каталог…")
        threading.Thread(target=self._load_worker, args=("", url), daemon=True).start()

    def _load_worker(self, parent, url):
        # корінь ("") — autoindex-каталог, якщо це тека, або сторінка, якщо в URL є
        # розширення файлу; вузол-файл, позначений як "сторінка" (🔗), розгортаємо
        # через пошук посилань на ній самій
        node = self.nodes.get(parent)
        page_mode = (not node["is_dir"]) if node else looks_like_file_url(url)
        stats = {}
        try:
            items = (list_page_links(url, self.auth(), stats=stats) if page_mode
                    else list_directory(url, self.auth(), stats=stats))
            self.msgq.put(("children", (parent, items)))
            extra = []
            if stats.get("out_of_scope"):
                extra.append(f"поза межами теки: {stats['out_of_scope']}")
            if stats.get("external"):
                extra.append(f"на інші сайти: {stats['external']}")
            suffix = f"  ({'; '.join(extra)} — не показано)" if extra else ""
            self.msgq.put(("status", f"{url} — {len(items)} елементів{suffix}"))
            if extra:
                self.msgq.put(("log", f"   ⓘ {url}\n     {'; '.join(extra)} "
                                      f"— відфільтровано (поза обраною текою або інший сайт)"))
            return
        except HTTPError as e:
            self.msgq.put(("log", f"[HTTP {e.code}] {url}"))
            self.msgq.put(("status", f"Помилка HTTP {e.code}"))
        except URLError as e:
            reason = getattr(e, "reason", e)
            hint = self._tls_hint(reason) if isinstance(reason, ssl.SSLCertVerificationError) else ""
            self.msgq.put(("log", f"[мережа] {url} — {reason}{hint}"))
            self.msgq.put(("status", "Помилка мережі"))
        except Exception as e:
            self.msgq.put(("log", f"[помилка] {url} — {e}"))
        # дочитати не вдалося — повернути каталог у стан «не завантажено», щоб можна було повторити
        if parent:
            self.msgq.put(("reset_load", parent))

    def _insert_children(self, parent, items):
        # прибрати заглушку "…", якщо вона ще висить
        for k in self.tree.get_children(parent):
            if k not in self.nodes:
                self.tree.delete(k)
        inherit = ON if (parent and self.nodes[parent]["state"] == ON) else OFF
        dup = 0
        for it in items:
            # той самий URL уже показаний десь у дереві (напр. пряме посилання-шорткат
            # на сторінці веде туди ж, куди й вкладена папка) — не дублювати рядок
            existing = self.seen_urls.get(it["url"])
            if existing and existing in self.nodes:
                dup += 1
                continue
            icon = "📁 " if it["is_dir"] else ("🔗 " if it.get("page") else "📄 ")
            tag = "dir" if it["is_dir"] else ("page" if it.get("page") else "")
            iid = self.tree.insert(
                parent, "end",
                text=icon + it["name"],
                values=(GLYPH[inherit],
                        ("?" if it["is_dir"] else bytes_to_human(it["size"])),
                        it["date"] or "-"),
                tags=(tag,) if tag else (),
            )
            self.nodes[iid] = {**it, "state": inherit, "loaded": False}
            self.seen_urls[it["url"]] = iid
            if it["is_dir"] or it.get("page"):
                self.tree.insert(iid, "end", text="…")  # заглушка для стрілки —
                                                         # папки й HTML-сторінки можна розгорнути
        if parent:
            self.nodes[parent]["loaded"] = True
        self._refresh_parents(parent)
        self._refresh_sizes(parent)
        if dup:
            self.msgq.put(("log", f"   (приховано повторів: {dup} — це посилання вже є деінде в дереві)"))

    def on_expand(self, _event):
        iid = self.tree.focus() or self.tree.selection()
        iid = iid if isinstance(iid, str) else (iid[0] if iid else None)
        if not iid:
            return
        self._ensure_loaded(iid)

    def _ensure_loaded(self, iid):
        node = self.nodes.get(iid)
        if not node or not (node["is_dir"] or node.get("page")) or node["loaded"]:
            return
        kids = self.tree.get_children(iid)
        if len(kids) == 1 and not self.nodes.get(kids[0]):
            self.tree.delete(kids[0])
        node["loaded"] = True
        threading.Thread(target=self._load_worker,
                         args=(iid, node["url"]), daemon=True).start()

    def scan_all(self, _tries=0):
        """Рекурсивно обійти весь каталог (може бути довго)."""
        if not self.tree.get_children():
            if _tries == 0:
                self.load_root()
            if _tries < 20:
                self.after(1000, lambda: self.scan_all(_tries + 1))
            else:
                self.status.set("Не вдалося прочитати кореневий каталог — скан скасовано.")
            return
        if self.busy:
            return
        self.busy = True
        self.stop_evt.clear()
        self.stop_btn.config(state="normal")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def scan_subtree(self, iid):
        """Рекурсивно обійти лише одну вибрану папку."""
        node = self.nodes.get(iid)
        if not node or not node["is_dir"] or self.busy:
            return
        self.busy = True
        self.stop_evt.clear()
        self.stop_btn.config(state="normal")
        self.status.set(f"Рекурсивне сканування: {node['name']}…")
        self._ensure_loaded(iid)
        threading.Thread(target=self._scan_worker,
                         args=(node["url"],), daemon=True).start()

    def _scan_worker(self, prefix=None):
        seen, empty = 0, 0
        totals = {}
        while not self.stop_evt.is_set():
            pending = [i for i, n in self.nodes.items()
                       if n["is_dir"] and not n["loaded"]
                       and (prefix is None or n["url"].startswith(prefix))]
            if not pending:
                empty += 1                       # діти щойно просканованих ще їдуть у чергу
                if empty >= 3:
                    break
                threading.Event().wait(0.3)
                continue
            empty = 0
            for iid in pending:
                if self.stop_evt.is_set():
                    break
                node = self.nodes[iid]
                node["loaded"] = True
                try:
                    stats = {}
                    items = list_directory(node["url"], self.auth(), stats=stats)
                    self.msgq.put(("children", (iid, items)))
                    seen += 1
                    for k, v in stats.items():
                        totals[k] = totals.get(k, 0) + v
                    self.msgq.put(("status", f"Просканував каталогів: {seen}"))
                except Exception as e:
                    self.msgq.put(("log", f"[скан] {node['url']} — {e}"))
            threading.Event().wait(0.2)
        extra = []
        if totals.get("out_of_scope"):
            extra.append(f"поза межами тек: {totals['out_of_scope']}")
        if totals.get("external"):
            extra.append(f"на інші сайти: {totals['external']}")
        tail = f"; відфільтровано — {', '.join(extra)}" if extra else ""
        self.msgq.put(("done", f"Сканування завершено. Каталогів: {seen}{tail}"))

    # ------------------------------------------------------ галочки
    def on_click(self, event):
        if self.tree.identify_region(event.x, event.y) != "cell":
            return
        if self.tree.identify_column(event.x) != "#1":
            return
        iid = self.tree.identify_row(event.y)
        if iid not in self.nodes:
            return
        sel = self.tree.selection()
        if len(sel) > 1 and iid in sel:
            self._toggle_many(sel, iid)     # клац по галочці всередині виділення → на всі
        else:
            self.toggle(iid)
        return "break"

    def on_space(self, _event):
        sel = self.tree.selection()
        focus = self.tree.focus()
        if len(sel) > 1:
            self._toggle_many(sel, focus if focus in sel else sel[0])
        elif focus in self.nodes:
            self.toggle(focus)
        return "break"

    def _toggle_many(self, iids, anchor):
        rows = [i for i in iids if i in self.nodes]
        if not rows or anchor not in self.nodes:
            return
        target = OFF if self.nodes[anchor]["state"] in (ON, PART) else ON
        parents = set()
        for r in rows:
            self._set_state(r, target)
            parents.add(self.tree.parent(r))
        for p in parents:
            self._refresh_parents(p)
        self._update_status_counts()

    def toggle(self, iid):
        new = OFF if self.nodes[iid]["state"] in (ON, PART) else ON
        self._set_state(iid, new)
        self._refresh_parents(self.tree.parent(iid))
        self._update_status_counts()

    def _set_state(self, iid, state):
        self.nodes[iid]["state"] = state
        self.tree.set(iid, "sel", GLYPH[state])
        for kid in self.tree.get_children(iid):
            if kid in self.nodes:
                self._set_state(kid, state)

    def _refresh_parents(self, iid):
        while iid:
            kids = [k for k in self.tree.get_children(iid) if k in self.nodes]
            if kids:
                states = {self.nodes[k]["state"] for k in kids}
                st = ON if states == {ON} else (OFF if states == {OFF} else PART)
                self.nodes[iid]["state"] = st
                self.tree.set(iid, "sel", GLYPH[st])
            iid = self.tree.parent(iid)

    # ------------------------------------------------------ розмір папок
    def _dir_size(self, iid):
        """Сума розмірів прочитаних нащадків. Повертає (байти, чи_повна_картина)."""
        total, complete = 0, True
        for kid in self.tree.get_children(iid):
            n = self.nodes.get(kid)
            if not n:                       # заглушка "…" — вміст ще не читали
                complete = False
                continue
            if n["is_dir"]:
                total += n.get("_dsize", 0)
                complete = complete and n.get("_dcomplete", False)
            else:
                total += n["size"]
        return total, complete

    def _size_text(self, total, complete):
        if total:
            return ("" if complete else "≥ ") + bytes_to_human(total)
        return "-" if complete else "?"

    def _refresh_sizes(self, iid):
        """Оновити стовпчик «Розмір» для папки iid та всіх її батьків."""
        while iid:
            n = self.nodes.get(iid)
            if n and n["is_dir"]:
                total, complete = self._dir_size(iid)
                n["_dsize"], n["_dcomplete"] = total, complete
                self.tree.set(iid, "size", self._size_text(total, complete))
            iid = self.tree.parent(iid)

    def _refresh_all_sizes(self):
        """Повний перерахунок знизу вгору (після «Сканувати все»)."""
        def rec(iid):
            for kid in self.tree.get_children(iid):
                if self.nodes.get(kid, {}).get("is_dir"):
                    rec(kid)
            n = self.nodes.get(iid)
            if n and n["is_dir"]:
                total, complete = self._dir_size(iid)
                n["_dsize"], n["_dcomplete"] = total, complete
                self.tree.set(iid, "size", self._size_text(total, complete))
        for r in self.tree.get_children(""):
            rec(r)

    def set_all(self, state):
        for iid in self.tree.get_children(""):
            self._set_state(iid, state)
        self._update_status_counts()

    def invert(self):
        for iid, n in self.nodes.items():
            if not n["is_dir"]:
                n["state"] = OFF if n["state"] == ON else ON
                self.tree.set(iid, "sel", GLYPH[n["state"]])
        for iid in self.tree.get_children(""):
            self._refresh_parents(iid)
        self._update_status_counts()

    def select_by_mask(self):
        import fnmatch
        masks = [m.strip() for m in self.mask_var.get().split() if m.strip()]
        if not masks:
            return
        cnt = 0
        for iid, n in self.nodes.items():
            if n["is_dir"]:
                continue
            if any(fnmatch.fnmatch(n["name"].lower(), m.lower()) for m in masks):
                n["state"] = ON
                self.tree.set(iid, "sel", GLYPH[ON])
                cnt += 1
        for iid in self.tree.get_children(""):
            self._refresh_parents(iid)
        self.say(f"За маскою вибрано файлів: {cnt}")
        self._update_status_counts()

    def select_pages_only(self):
        """Позначити лише HTML-сторінки (🔗) — вже завантажені в дерево."""
        cnt = 0
        for iid, n in self.nodes.items():
            if n["is_dir"] or not n.get("page"):
                continue
            n["state"] = ON
            self.tree.set(iid, "sel", GLYPH[ON])
            cnt += 1
        for iid in self.tree.get_children(""):
            self._refresh_parents(iid)
        self.say(f"Вибрано сторінок: {cnt}"
                + ("" if cnt else " (розгорни/просканируй потрібні папки, щоб їх побачити)"))
        self._update_status_counts()

    def select_files_only(self):
        """Позначити лише звичайні файли (не HTML-сторінки, не папки)."""
        cnt = 0
        for iid, n in self.nodes.items():
            if n["is_dir"] or n.get("page"):
                continue
            n["state"] = ON
            self.tree.set(iid, "sel", GLYPH[ON])
            cnt += 1
        for iid in self.tree.get_children(""):
            self._refresh_parents(iid)
        self.say(f"Вибрано файлів (без сторінок): {cnt}")
        self._update_status_counts()

    def selected_files(self):
        return [(iid, n) for iid, n in self.nodes.items()
                if not n["is_dir"] and n["state"] == ON]

    def _update_status_counts(self):
        files = self.selected_files()
        total = sum(n["size"] for _, n in files)
        self.status.set(f"Відмічено галочками: {len(files)} файлів  •  {bytes_to_human(total)}")

    # ------------------------------------------------------ експорт
    def export_list(self):
        files = self.selected_files()
        if not files:
            messagebox.showinfo("Список", "Нічого не вибрано.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            initialfile="urls.txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for _, n in files:
                f.write(n["url"] + "\n")
        self.say(f"Збережено {len(files)} URL → {path}")
        self.say("Можна згодувати в:  wget -x -c -i urls.txt   або   aria2c -i urls.txt -x8 -j4 -c")

    # ---------------------------------------------- rclone-фільтр
    def _rclone_filter_text(self):
        """Зі стану галочок → rclone --filter-from: цілі папки як /шлях/**, окремі файли поштучно."""
        root = self.url_var.get().strip()
        host = ""
        if root.startswith(("http://", "https://")):
            pr = urlparse(root)
            host = f"{pr.scheme}://{pr.netloc}"

        def esc(seg):
            for ch in "\\*?[]{}":
                seg = seg.replace(ch, "\\" + ch)
            return seg

        def path_of(n):
            p = unquote(urlparse(n["url"]).path)
            return "/".join(esc(s) for s in p.split("/"))

        lines = []

        def walk(parent):
            for iid in self.tree.get_children(parent):
                n = self.nodes.get(iid)
                if not n:
                    continue
                if n["is_dir"]:
                    if n["state"] == ON:                       # ціла папка
                        lines.append(f"+ {path_of(n).rstrip('/')}/**")
                    elif n["state"] == PART:                   # частково — углиб
                        walk(iid)
                elif n["state"] == ON:                         # окремий файл
                    lines.append(f"+ {path_of(n)}")

        walk("")
        if not lines:
            return None
        head = ["# rclone selection manifest"]
        if host:
            head.append(f"# HTTP_ROOT = {host}")
        return "\n".join(head + lines + ["- **"]) + "\n"

    def export_rclone_filter(self):
        txt = self._rclone_filter_text()
        if not txt:
            messagebox.showinfo("rclone-фільтр", "Нічого не вибрано.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            initialfile="rclone_filter.txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(txt)
        self.clipboard_clear()
        self.clipboard_append(txt)
        self.update_idletasks()
        self.say(f"rclone-фільтр → {path}  (і скопійовано в буфер):")
        for l in txt.splitlines():
            self.say("  " + l)

    # ------------------------------------------------------ сторінка з ресурсами
    def save_current_page(self):
        """Зберегти відкритий (кореневий) URL повністю: HTML + img/css/js — для офлайну."""
        url = self.url_var.get().strip()
        if not url.startswith(("http://", "https://")):
            messagebox.showwarning("URL", "Спершу вкажіть і відкрийте URL сторінки.")
            return
        self._apply_tls()
        out = self.dir_var.get()
        os.makedirs(out, exist_ok=True)
        out_html = os.path.join(out, "index.html")
        self.dl_report = []
        self.say(f"Зберігаю поточну сторінку → {out_html}")
        threading.Thread(target=self._save_page_worker, args=(url, out_html, out), daemon=True).start()

    def _save_page_worker(self, url, out_html, out_root):
        try:
            self._mirror_page(url, out_html, base=url, out_root=out_root)
            self.msgq.put(("status", f"Сторінку збережено: {out_html}"))
        except Exception as e:
            self.msgq.put(("log", f"[!] не вдалося зберегти сторінку — {e}"))
            self.msgq.put(("status", "Помилка збереження сторінки"))
            self.msgq.put(("report", {"kind": "page", "name": os.path.basename(out_html),
                                      "url": url, "status": "fail", "error": str(e), "source": None}))
        self.msgq.put(("report_done", None))

    def _looks_like_html(self, url):
        """Швидка перевірка перед завантаженням-з-ресурсами: чи це справді HTML.
        Розширення .html/.php/… — довіряємо одразу; без розширення — питаємо HEAD."""
        ext = os.path.splitext(urlparse(url).path)[1].lower()
        if ext in _STRONG_PAGE_EXTS:
            return True
        try:
            req = Request(url, method="HEAD", headers={"User-Agent": UA})
            with urlopen(req, timeout=TIMEOUT, context=SSL_CTX) as r:
                return "html" in (r.headers.get_content_type() or "").lower()
        except Exception:
            return False

    def _mirror_page(self, url, out_html_path, base=None, out_root=None, source=None):
        """Зберігає HTML-сторінку разом з img/css/js; посилання на них переписує
        на локальні відносні шляхи (тека "<ім'я>_files" поруч з html-файлом).
        Якщо задано base/out_root — додатково переписує <a href> на інші сторінки
        в межах каталогу на їхній обчислений локальний шлях (навіть якщо та сторінка
        ще не завантажена: щойно її теж скачають цим же способом — посилання запрацює).
        source — {"name","url"} звідки на цю сторінку вели (для звіту про помилки)."""
        page_name = os.path.basename(urlparse(url).path.rstrip("/")) or url
        with fetch(url, self.auth()) as resp:
            raw = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
        html = raw.decode(charset, errors="replace")

        parser = PageAssetParser(html)
        parser.feed(html)

        refs = []
        for start, end, tag, attrs, raw_tag in parser.tags:
            attr_names = _ASSET_ATTRS.get(tag)
            if not attr_names:
                continue
            if tag == "link":
                rel_attr = (attrs.get("rel") or "").lower()
                if not any(k in rel_attr for k in ("stylesheet", "icon")):
                    continue
            for attr in attr_names:
                val = attrs.get(attr)
                if not val or val.startswith(("data:", "mailto:", "javascript:", "#")):
                    continue
                full = urljoin(url, val)
                if urlparse(full).scheme not in ("http", "https"):
                    continue
                refs.append((start, end, raw_tag, attr, val, full))

        base_name = os.path.splitext(os.path.basename(out_html_path))[0] or "index"
        assets_dirname = base_name + "_files"
        assets_dir = os.path.join(os.path.dirname(out_html_path), assets_dirname)

        url_to_local, used_names = {}, set()
        ok = err = 0
        for _, _, _, _, _, full in refs:
            if full in url_to_local:
                continue
            local_name = _asset_local_name(full, used_names)
            try:
                with fetch(full, self.auth()) as ar:
                    data = ar.read()
                os.makedirs(assets_dir, exist_ok=True)
                with open(os.path.join(assets_dir, local_name), "wb") as f:
                    f.write(data)
                url_to_local[full] = assets_dirname + "/" + local_name
                ok += 1
            except Exception as e:
                url_to_local[full] = None
                err += 1
                self.msgq.put(("log", f"   [ресурс не завантажено] {full} — {e}"))
                self.msgq.put(("report", {
                    "kind": "asset",
                    "name": unquote(urlparse(full).path.rsplit("/", 1)[-1]) or full,
                    "url": full, "status": "fail", "error": str(e),
                    "source": {"name": page_name, "url": url},
                }))

        # точкова заміна значення атрибута в сирому тексті кожного тега (за офсетом)
        tag_edits = {}
        for start, end, raw_tag, attr, val, full in refs:
            local = url_to_local.get(full)
            if not local:
                continue
            cur = tag_edits.get((start, end), raw_tag)
            tag_edits[(start, end)] = _replace_attr_value(cur, attr, val, local)

        # <a href> на інші сторінки того ж каталогу — на їхній (майбутній) локальний шлях
        if base and out_root:
            bp = unquote(base_dir_path(base))
            base_netloc = urlparse(base).netloc
            html_dir = os.path.dirname(out_html_path)
            for start, end, tag, attrs, raw_tag in parser.tags:
                if tag != "a":
                    continue
                href = attrs.get("href")
                if not href or href.startswith(("mailto:", "javascript:", "#")):
                    continue
                full = urljoin(url, href)
                if urlparse(full).netloc != base_netloc:
                    continue
                p = unquote(urlparse(full).path)
                if not p.startswith(bp) or p == bp:
                    continue
                rel = p[len(bp):].lstrip("/")
                if not rel:
                    continue
                target = os.path.join(out_root, *[re.sub(r'[<>:"|?*]', "_", s)
                                                   for s in rel.split("/") if s])
                if not target.lower().endswith((".html", ".htm")) and is_page_url(full):
                    target += ".html"
                local_rel = os.path.relpath(target, html_dir).replace(os.sep, "/")
                cur = tag_edits.get((start, end), raw_tag)
                new_raw = _replace_attr_value(cur, "href", href, local_rel)
                if new_raw != cur:
                    tag_edits[(start, end)] = new_raw

        pieces, cursor = [], 0
        for (start, end), new_raw in sorted(tag_edits.items()):
            pieces.append(html[cursor:start])
            pieces.append(new_raw)
            cursor = end
        pieces.append(html[cursor:])
        new_html = "".join(pieces)

        os.makedirs(os.path.dirname(out_html_path) or ".", exist_ok=True)
        with open(out_html_path, "w", encoding="utf-8") as f:
            f.write(new_html)

        self.msgq.put(("log", f"✔ сторінка: {out_html_path}  (ресурсів: {ok}"
                              + (f", помилок: {err}" if err else "") + ")"))
        self.msgq.put(("report", {"kind": "page", "name": page_name, "url": url,
                                  "status": "ok", "size": os.path.getsize(out_html_path),
                                  "source": source}))
        return out_html_path

    # ------------------------------------------------------ локальний навігатор
    def build_navigator_dialog(self):
        """Обрати вже скачану папку (свіжу чи стару) і побудувати для неї
        HTML-навігатор — переходи по дереву в браузері замість провідника."""
        d = filedialog.askdirectory(initialdir=self.dir_var.get(),
                                    title="Папка зі скачаними файлами")
        if not d:
            return
        self.say(f"Створюю навігатор для: {d}")
        self.status.set("Будую навігатор…")
        threading.Thread(target=self._build_navigator_worker, args=(d,), daemon=True).start()

    def _build_navigator_worker(self, root_dir):
        def progress(n):
            if n % 20 == 0:
                self.msgq.put(("status", f"Навігатор: оброблено папок {n}…"))
        try:
            idx = build_local_navigator(root_dir, progress_cb=progress)
            self.msgq.put(("log", f"✔ Навігатор готовий: {idx}"))
            self.msgq.put(("status", "Навігатор готовий — відкриваю в браузері…"))
            try:
                webbrowser.open(pathlib.Path(idx).as_uri())
            except Exception:
                pass
        except Exception as e:
            self.msgq.put(("log", f"[!] не вдалося створити навігатор — {e}"))
            self.msgq.put(("status", "Помилка створення навігатора"))

    # ------------------------------------------------------ завантаження
    def pick_dir(self):
        d = filedialog.askdirectory(initialdir=self.dir_var.get())
        if d:
            self.dir_var.set(d)

    def _node_source(self, iid):
        """Найближчий батько вузла в дереві (папка/сторінка) — звідки на нього
        веде посилання; для звіту про помилки, щоб знати, де шукати повторно."""
        p = self.tree.parent(iid)
        n = self.nodes.get(p)
        if n:
            return {"name": n["name"], "url": n["url"]}
        return {"name": "(корінь)", "url": self.url_var.get().strip()}

    def start_download(self):
        if self.busy:
            return
        sel = self.selected_files()
        files = [(n, self._node_source(iid)) for iid, n in sel]
        if not files:
            messagebox.showinfo("Завантаження", "Спершу відмітьте, що качати.")
            return
        self._apply_tls()
        if self.no_verify_var.get() and self.auth():
            if not messagebox.askyesno(
                    "Небезпечно",
                    "Перевірку сертифіката вимкнено, але задано логін/пароль.\n"
                    "За таким з'єднанням їх можна перехопити. Продовжити?"):
                return
        out = self.dir_var.get()
        os.makedirs(out, exist_ok=True)

        self.busy = True
        self.stop_evt.clear()
        self.dl_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.prog["value"] = 0
        self.dl_report = []

        q = queue.Queue()
        for item in files:
            q.put(item)

        base = self.url_var.get().strip()
        counter = {"done": 0, "total": len(files), "err": 0}
        lock = threading.Lock()

        def worker():
            while not self.stop_evt.is_set():
                try:
                    node, source = q.get_nowait()
                except queue.Empty:
                    return
                try:
                    self._download_one(node, base, out, source=source)
                except Exception as e:
                    with lock:
                        counter["err"] += 1
                    self.msgq.put(("log", f"[!] {node['name']} — {e}"))
                    self.msgq.put(("report", {"kind": "file", "name": node["name"],
                                              "url": node["url"], "status": "fail",
                                              "error": str(e), "source": source}))
                finally:
                    with lock:
                        counter["done"] += 1
                        self.msgq.put(("progress", (counter["done"], counter["total"])))

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(max(1, self.threads_var.get()))]
        for t in threads:
            t.start()

        def waiter():
            for t in threads:
                t.join()
            msg = (f"Готово: {counter['done'] - counter['err']} з {counter['total']}"
                   + (f", помилок: {counter['err']}" if counter["err"] else ""))
            self.msgq.put(("done", msg))
            self.msgq.put(("report_done", None))

        threading.Thread(target=waiter, daemon=True).start()

    def _dest_path(self, node, base, out_root):
        url = node["url"]
        if self.flat_var.get():
            rel = node["name"]
        else:
            bp = base_dir_path(base)
            p = unquote(urlparse(url).path)
            rel = p[len(unquote(bp)):].lstrip("/") if p.startswith(unquote(bp)) else node["name"]
        rel = rel.replace("\\", "/")
        return os.path.join(out_root, *[re.sub(r'[<>:"|?*]', "_", part)
                                        for part in rel.split("/") if part])

    def _download_one(self, node, base, out_root, source=None):
        safe = self._dest_path(node, base, out_root)
        rel = os.path.relpath(safe, out_root).replace(os.sep, "/")

        if node.get("page") and self.page_assets_var.get() and self._looks_like_html(node["url"]):
            if not safe.lower().endswith((".html", ".htm")):
                safe += ".html"
            os.makedirs(os.path.dirname(safe) or out_root, exist_ok=True)
            self._mirror_page(node["url"], safe, base=base, out_root=out_root, source=source)
            return

        self._plain_download(node["url"], safe, rel, node["size"], source=source)

    def _plain_download(self, url, safe, rel, expected_size, source=None):
        os.makedirs(os.path.dirname(safe) or ".", exist_ok=True)

        if os.path.exists(safe) and expected_size and os.path.getsize(safe) == expected_size:
            self.msgq.put(("log", f"= пропуск (вже є): {rel}"))
            self.msgq.put(("report", {"kind": "file", "name": rel, "url": url,
                                      "status": "skip", "size": expected_size, "source": source}))
            return

        tmp = safe + ".part"
        pos = os.path.getsize(tmp) if os.path.exists(tmp) else 0
        resp = fetch(url, self.auth(), range_from=pos if pos else None)
        mode = "ab"
        if getattr(resp, "status", resp.getcode()) != 206:
            pos, mode = 0, "wb"

        self.msgq.put(("log", f"↓ {rel}"))
        with resp, open(tmp, mode) as f:
            while not self.stop_evt.is_set():
                chunk = resp.read(262144)
                if not chunk:
                    break
                f.write(chunk)
        if self.stop_evt.is_set():
            self.msgq.put(("log", f"|| зупинено: {rel} (продовжиться з {bytes_to_human(os.path.getsize(tmp))})"))
            self.msgq.put(("report", {"kind": "file", "name": rel, "url": url,
                                      "status": "stopped", "source": source}))
            return
        os.replace(tmp, safe)
        self.msgq.put(("log", f"✔ {rel}"))
        self.msgq.put(("report", {"kind": "file", "name": rel, "url": url,
                                  "status": "ok", "size": os.path.getsize(safe), "source": source}))

    # ------------------------------------------------------ звіт про завантаження
    def _show_report(self):
        recs = self.dl_report
        if not recs:
            return
        pages = [r for r in recs if r["kind"] == "page"]
        files = [r for r in recs if r["kind"] == "file"]
        assets = [r for r in recs if r["kind"] == "asset"]

        ok_pages = [r for r in pages if r["status"] == "ok"]
        ok_files = [r for r in files if r["status"] == "ok"]
        skip_files = [r for r in files if r["status"] == "skip"]
        stopped = [r for r in files if r["status"] == "stopped"]
        fail_pages = [r for r in pages if r["status"] == "fail"]
        fail_files = [r for r in files if r["status"] == "fail"]
        fail_assets = [r for r in assets if r["status"] == "fail"]
        n_fail = len(fail_pages) + len(fail_files) + len(fail_assets)
        total = sum(r.get("size", 0) for r in ok_pages + ok_files)

        L = ["=== ЗВІТ ПРО ЗАВАНТАЖЕННЯ ===", ""]
        if ok_pages:
            L.append(f"Сторінок збережено: {len(ok_pages)}")
        if ok_files:
            L.append(f"Файлів завантажено: {len(ok_files)}")
        L.append(f"Разом обсяг: {bytes_to_human(total)}")
        if skip_files:
            L.append(f"Пропущено (вже було на диску): {len(skip_files)}")
        if stopped:
            L.append(f"Перервано («Стоп»): {len(stopped)}")
        L.append(f"Помилок: {n_fail}")

        def block(title, rows, label):
            if not rows:
                return
            L.append("")
            L.append(f"--- {title} ---")
            for r in rows:
                L.append(f"[{label}] {r['name']}")
                L.append(f"    {r['url']}")
                L.append(f"    помилка: {r.get('error', '?')}")
                s = r.get("source")
                if s:
                    L.append(f"    джерело (де шукати посилання): {s['name']}  —  {s['url']}")

        block("СТОРІНКИ, ЯКІ НЕ ВДАЛОСЯ ЗБЕРЕГТИ", fail_pages, "сторінка")
        block("ФАЙЛИ, ЯКІ НЕ ВДАЛОСЯ ЗАВАНТАЖИТИ", fail_files, "файл")
        block("ЗОБРАЖЕННЯ/РЕСУРСИ СТОРІНОК, ЯКІ НЕ ВДАЛОСЯ ЗАВАНТАЖИТИ", fail_assets, "ресурс")

        if not n_fail:
            L.append("")
            L.append("✅ Усе завантажилось без помилок.")

        self._open_report_window("\n".join(L))

    def _open_report_window(self, text):
        win = tk.Toplevel(self)
        win.title("Звіт про завантаження")
        win.geometry("780x540")

        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=6, pady=4)
        txt = tk.Text(win, wrap="word", font=("Consolas", 9), undo=False)

        ttk.Button(bar, text="Копіювати все",
                  command=lambda: self._copy_text_widget(txt)).pack(side="left")
        ttk.Button(bar, text="Закрити", command=win.destroy).pack(side="right")

        txt.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        txt.insert("1.0", text)
        txt.configure(state="disabled")   # тільки читання; виділення й копіювання лишаються доступні

        txt.bind("<Control-KeyPress>", lambda e: self._text_ctrl_key(e, txt))

        m = tk.Menu(txt, tearoff=0)
        m.add_command(label="Копіювати виділене", command=lambda: txt.event_generate("<<Copy>>"))
        m.add_command(label="Виділити все", command=lambda: txt.tag_add("sel", "1.0", "end"))
        m.add_command(label="Копіювати все", command=lambda: self._copy_text_widget(txt))

        def popup(e):
            try:
                m.tk_popup(e.x_root, e.y_root)
            finally:
                m.grab_release()

        txt.bind("<Button-3>", popup)
        win.transient(self)
        txt.focus_set()

    def stop(self):
        self.stop_evt.set()
        self.status.set("Зупиняю…")


if __name__ == "__main__":
    App().mainloop()