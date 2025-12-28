<p align="right">
  <a href="README.md"><img src="https://cdn.jsdelivr.net/gh/hampusborgos/country-flags@main/svg/ru.svg" alt="RU" width="20" /> RU</a> |
  <a href="README.en.md"><img src="https://cdn.jsdelivr.net/gh/hampusborgos/country-flags@main/svg/us.svg" alt="EN" width="20" /> EN</a>
</p>

<a id="en"></a>

# Reshala Tool 🚀 v3.x

![Reshala logo](https://raw.githubusercontent.com/DonMatteoVPN/Reshala-Remnawave-Bedolaga/main/assets/reshala-logo.jpg)

<p align="center">
  <br>
  <strong>⚠️ ATTENTION: THIS PROJECT IS IN ACTIVE DEVELOPMENT (ALPHA STAGE) ⚠️</strong>
  <br>
  <em>Use at your own risk. Bugs and unpredictable behavior are expected.</em>
  <br>
</p>

### WHAT IS THIS TOOL?

Reshala is a simple console control panel that helps you keep your servers and fleet under control.

It:
- prepares a server “from zero to ready” (cleans junk, fixes the system, tunes network settings);
- **secures the server** with a comprehensive security module (Firewall, Fail2Ban, Hardening);
- shows a clear dashboard with CPU/RAM/disk and channel usage;
- has a **Skynet** mode to control many servers from a single screen;
- installs and maintains the **Remnawave panel and its nodes** on one or many servers;
- supports lightweight widgets and plugins so you can add your own tricks.

The idea is simple: less manual admin work, more time for your business.

---

### 🎛 DASHBOARD

When you start the script, you get a **control panel**, not a black hole:
- **Visuals:** CPU / RAM / Disk usage bars.
- **Honest math:** can run an **official Ookla speedtest** and estimate **how many real users your node can handle**. This calculation also works correctly in agent mode (Skynet).
- **Status:** kernel version, virtualization, country, ping, and status of main services.
- **WIDGETS:** small, toggleable widgets below the panel (crypto price, Docker state, network activity), which can be toggled. Output is auto-aligned, and data is cached to minimize load.

---

### 🌐 [0] SKYNET: FLEET CONTROL

No more SSHing into each server by hand.
*   **Single control plane:** Add all your servers to the database and manage them from one place.
*   **Teleport:** Instantly connect to any server. The script manages keys for you.
*   **Auto-capture:** If a remote server doesn't have Reshala, Skynet can install it automatically.
*   **Categorized Commands:** Execute commands across your entire fleet by choosing from a convenient, categorized menu (diagnostics, system, security, etc.).

---

### 📂 MENU OVERVIEW

#### [1] 🔧 MAINTENANCE
Everything that keeps the server stable and responsive.
*   **System Heal & Update:** Helps revive older Ubuntu versions, gently fixing repositories and packages.
*   **Network Boost:** Applies a ready-made set of BBR tweaks for better speed in a few steps.
*   **Channel Check:** Measures real bandwidth and roughly estimates how many users this server can handle.

#### [2] 📜 DIAGNOSTICS
Stop typing `docker logs -f ...` by hand.
*   Quick access to logs for Reshala itself, the Remnawave panel, the node (Xray), or the Bot.
*   Instant problem diagnosis with a clean exit via `CTRL+C`.

#### [3] 🐳 DOCKER MANAGEMENT
Docker loves to eat disk space. This section keeps it in check.
*   Shows containers, images, volumes, and networks.
*   Prunes garbage (cache, old containers, dangling volumes) with a single command and confirmation.
*   Provides handy menus for starting, stopping, restarting, viewing logs, and inspecting containers.

#### [4] 💿 REMNAWAVE: INSTALL & CONTROL
This section groups all Remnawave workflows.
- **Panel only** – installs the Remnawave panel, creates an admin, and can immediately enable HTTPS.
- **Panel + node** – sets up the panel and the first node on the same server.
- **Node installation wizard** – installs nodes on this server, on one remote server (via Skynet), or on several at once.
- **Manage installation** – restart, view logs, and review key information.

#### [s] 🛡️ SECURITY
A comprehensive module for basic server hardening.
*   **Security Status:** an overall summary of all protection components.
*   **Firewall (UFW):** a wizard for configuring rules, with ready-made profiles for nodes.
*   **Fail2Ban:** automatically blocks attackers based on SSH logs.
*   **Kernel Hardening (sysctl):** applies proven security settings at the kernel level.
*   **Backups:** create and restore security configurations.

#### [t] 🤖 TG NOTIFICATIONS
A module for Telegram integration. Currently under development.

---

## 📥 INSTALLATION

Once. Forever. Copy, paste, press Enter.

### Stable branch (main):
```bash
wget -O install.sh https://raw.githubusercontent.com/DonMatteoVPN/Reshala-Remnawave-Bedolaga/main/install.sh \
  && bash install.sh \
  && reshala
```

### Dev branch (dev) — **NOT for production**
```bash
wget -O install.sh https://raw.githubusercontent.com/DonMatteoVPN/Reshala-Remnawave-Bedolaga/dev/install.sh \
  && bash install.sh \
  && reshala
```

---

## 🚀 HOW TO RUN

Just type in your console:
```bash
sudo reshala
```
**If something goes wrong, remove traces of the failed installation:**
```bash
rm -f /usr/local/bin/reshala && rm -rf /opt/reshala && rm -f install.sh
```

---

## 🧩 IF YOU WANT TO HACK ON THE CODE

This README is for users. If you are a developer who wants to extend Reshala, start with these documents:

- **`docs/STYLE_GUIDE.md`** — **(Must Read!)** The single source of truth for coding style, UI conventions, and using internal helpers.
- `WARP.md` — The development journal and a high-level architecture overview.
- `docs/GUIDE_MODULES.md` – How to write new modules and integrate them into the menu.
- `docs/GUIDE_SKYNET_WIDGETS.md` – How to build your own widgets and Skynet commands.

**The key rule:** before writing any code, you must study **`docs/STYLE_GUIDE.md`**.

---

## 🥃 FINAL WORD

This tool was built so you can focus on your business, not on admin work. See a bug? Report it. Like a feature? Use it.

**Good luck and stable profit.** 👊

### [💰 Small tip to support the author (for beer & nerves)](https://t.me/tribute/app?startapp=dxrn)
