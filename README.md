# XLXMonD

**XLXMonD** is a lightweight, high-performance Node.js / TypeScript microservice and real-time web dashboard for [XLXD](https://github.com/LX3JL/xlxd) multiprotocol reflectors (D-Star, DMR, YSF).

It connects directly to the XLXD JSON reporting UDP socket and log files, serving an interactive dashboard with live traffic, station geolocations, module statistics, and reflector status via WebSockets.

---

## Features

- **Real-Time Traffic Monitor**: Instant display of transmitting stations, nodes, and linked peers with low latency.
- **Interactive Station Map**: Live geolocation of transmitting stations (OMs) resolved against RadioID / DMR-MARC databases.
- **Module Management**: Customize module display order, labels, colors, and visibility filters (A to Z).
- **Reflector Directory**: Built-in worldwide reflector list with uptime tracking and direct dashboard links.
- **Stateless Authentication**: Optional private dashboard access using a CRC16-based passcode generator (`gencode`) — no database required.
- **Responsive Web UI**: Built-in light and dark themes, mobile-friendly design, and minimal templating for easy customization.

---

## Architecture & Network Ports

XLXMonD runs an HTTP web server and a WebSocket server, and communicates with your XLXD reflector over UDP:

| Port | Protocol | Direction | Description | Default |
| :--- | :--- | :--- | :--- | :--- |
| **7779** | TCP | Inbound | HTTP Web Dashboard | `__monitor_webserver_port__` |
| **8003** | TCP | Inbound | Real-time WebSocket feed | `__socketServerPort__` |
| **10001** | UDP | Outbound / Bi-dir | XLXD JSON reporting socket | `XLXD_PORTJSON` |

> [!NOTE]
> Ports can be customized in `src/config.ts`. Ensure inbound ports `7779` and `8003` are allowed in your firewall.

---

## Prerequisites

Before installing, ensure the following are installed on your system:

- **Node.js**: Version **18.x**, **20.x (LTS)**, or higher.
- **npm**: Version **9.x** or higher (bundled with Node.js).
- **Git**: For cloning the repository.
- **XLXD Reflector**: A running instance of XLXD with JSON reporting enabled.

---

## Installation Guide: Linux

Supported distributions: Debian, Ubuntu, Raspberry Pi OS, Rocky Linux, AlmaLinux, CentOS.

### 1. Install Node.js and Git

#### Debian / Ubuntu / Raspberry Pi OS:
```bash
sudo apt update
sudo apt install -y curl git build-essential

# Install Node.js 20.x LTS via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

#### RHEL / Rocky Linux / AlmaLinux:
```bash
sudo dnf install -y curl git gcc-c++ make
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
sudo dnf install -y nodejs
```

Verify the installation:
```bash
node -v
npm -v
git --version
```

### 2. Clone the Repository

Clone into `/opt` (or your preferred directory, e.g. `/home/pi/xlxmond`):

```bash
cd /opt
sudo git clone https://github.com/Avrahqedivra/xlxmond.git
cd xlxmond
sudo chown -R $USER:$USER /opt/xlxmond
```

### 3. Install Node Dependencies

```bash
npm install
```

### 4. Create and Edit Configuration

Copy the sample configuration file to `src/config.ts`:

```bash
cp src/config_sample.txt src/config.ts
nano src/config.ts
```

Configure key parameters:
- `XLXD_IP`: The IP address of your XLX reflector (use `'127.0.0.1'` if XLXMonD is on the same server).
- `XLXD_PORTJSON`: XLXD JSON reporting port (default: `10001`).
- `__localhost__`: Bind address (`'0.0.0.0'` to allow external access, or `'127.0.0.1'` if behind a reverse proxy).
- `__monitor_webserver_port__`: Dashboard HTTP port (default: `7779`).
- `__socketServerPort__`: WebSocket server port (default: `8003`).
- `__xlxdlog_file__`: Path to the XLXD log XML (default: `'/var/log/xlxd.xml'`).

### 5. Build the TypeScript Source

Whenever you change code or update `src/config.ts`, you must compile the TypeScript files:

```bash
npm run build
```

This compiles TypeScript files from `src/` into JavaScript in `dist/`.

### 6. Test Run

Launch XLXMonD from the terminal:

```bash
node ./dist/monitor.js
```

> [!IMPORTANT]
> **First Run Note:** On first launch, XLXMonD automatically downloads reference data (`subscriber_ids.json` from RadioID.net and `reflectorlist.xml` from rlx.lu) into `./assets/`. This may take 1 to 2 minutes depending on your internet connection. Wait until you see:
> ```text
> All files downloaded and saved. OK
> ```

Open your browser and navigate to:
```text
http://<your-server-ip>:7779
```

Press `Ctrl + C` in the terminal to stop the test run.

### 7. Configure as a Systemd Service (Auto-Start on Boot)

To run XLXMonD continuously in the background and start automatically at boot:

1. Create a systemd service file:
   ```bash
   sudo nano /etc/systemd/system/xlxmond.service
   ```

2. Paste the following configuration (adjust path or user if not using `/opt/xlxmond`):
   ```ini
   [Unit]
   Description=XLXMonD - XLX Reflector Real-Time Monitor
   After=network.target xlxd.service

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/opt/xlxmond
   ExecStart=/usr/bin/node /opt/xlxmond/dist/monitor.js
   Restart=always
   RestartSec=5
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable xlxmond
   sudo systemctl start xlxmond
   ```

4. Check service status and logs:
   ```bash
   sudo systemctl status xlxmond
   # View live logs:
   sudo journalctl -u xlxmond -f
   ```

### 8. Configure Firewall (Linux)

If using UFW (Ubuntu/Debian):
```bash
sudo ufw allow 7779/tcp comment "XLXMonD Web"
sudo ufw allow 8003/tcp comment "XLXMonD WebSocket"
sudo ufw reload
```

If using `firewalld` (CentOS/Rocky/Alma):
```bash
sudo firewall-cmd --permanent --add-port=7779/tcp
sudo firewall-cmd --permanent --add-port=8003/tcp
sudo firewall-cmd --reload
```

---

## Installation Guide: Windows

Supported versions: Windows 10, Windows 11, Windows Server 2016/2019/2022.

### 1. Install Prerequisites

1. **Install Node.js (LTS)**:
   - Download the Windows Installer (.msi) from [nodejs.org](https://nodejs.org/) (choose LTS), or via Windows Terminal / PowerShell:
     ```powershell
     winget install OpenJS.NodeJS.LTS
     ```
2. **Install Git**:
   - Download from [git-scm.com](https://git-scm.com/), or install via:
     ```powershell
     winget install Git.Git
     ```
3. Restart your PowerShell or Terminal session, then verify:
   ```powershell
   node -v
   npm -v
   git --version
   ```

### 2. Clone the Repository

Open PowerShell or Command Prompt and clone the repository:

```powershell
cd C:\
git clone https://github.com/Avrahqedivra/xlxmond.git
cd xlxmond
```

### 3. Install Node Dependencies

```powershell
npm install
```

### 4. Create and Edit Configuration

1. Copy the sample configuration:
   ```powershell
   Copy-Item src\config_sample.txt src\config.ts
   ```
   *(In Command Prompt, use: `copy src\config_sample.txt src\config.ts`)*

2. Open `src\config.ts` with your preferred editor (VS Code, Notepad++, or Notepad):
   ```powershell
   notepad src\config.ts
   ```

3. Configure parameters:
   - `XLXD_IP`: The IP address of your remote XLX reflector.
   - `XLXD_PORTJSON`: XLXD JSON reporting port (default: `10001`).
   - `__localhost__`: Bind address (`'0.0.0.0'` to allow connections from other machines on your LAN).
   - `__monitor_webserver_port__`: Dashboard web port (default: `7779`).
   - `__socketServerPort__`: WebSocket server port (default: `8003`).
   - `__xlxdlog_file__`: On Windows, set this to `'./log/xlxd.xml'` (a sample file is provided in `./log/`), or reference a mounted network share if accessing the remote XLXD server logs.

### 5. Build the TypeScript Source

Compile TypeScript to JavaScript:

```powershell
npm run build
```

> [!TIP]
> Each time you modify `src\config.ts`, remember to rerun `npm run build` so `dist\config.js` is regenerated.

### 6. Test Run

Start the monitor:

```powershell
node .\dist\monitor.js
```

Wait for the initial download of `subscriber_ids.json` and `reflectorlist.xml` to complete. Once finished, open your browser:
```text
http://localhost:7779
```

Press `Ctrl + C` in PowerShell to stop the application.

### 7. Run in the Background on Windows

To run XLXMonD as a persistent background process or Windows service:

#### Option A: Using PM2 (Recommended)
1. Install PM2 globally:
   ```powershell
   npm install -g pm2
   ```
2. Start XLXMonD under PM2:
   ```powershell
   pm2 start .\dist\monitor.js --name xlxmond
   pm2 save
   ```
3. To manage:
   ```powershell
   pm2 status
   pm2 logs xlxmond
   pm2 restart xlxmond
   ```

#### Option B: Using Windows Task Scheduler
Create a task in Windows Task Scheduler:
- **Trigger**: "At system startup" or "At log on"
- **Action**: "Start a program"
  - Program: `node.exe`
  - Arguments: `dist\monitor.js`
  - Start in: `C:\xlxmond`

### 8. Configure Windows Defender Firewall

If accessing the dashboard from another computer on your network, open PowerShell as Administrator and run:

```powershell
New-NetFirewallRule -DisplayName "XLXMonD Web (7779)" -Direction Inbound -LocalPort 7779 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "XLXMonD WebSocket (8003)" -Direction Inbound -LocalPort 8003 -Protocol TCP -Action Allow
```

---

## Authentication & Passcode Generator (`gencode`)

If you want to protect your dashboard with a password:

### 1. Enable Authentication in `src/config.ts`

Edit `src/config.ts`:
```typescript
export const __web_auth__: boolean = true;
export const __web_secret_key__: string = "YOUR_CUSTOM_SECRET_KEY";
```

Rebuild the application:
```bash
npm run build
```

### 2. Generate a Passcode for Users / Callsigns

Use the included `gencode` utility to compute the numeric passcode for a callsign or username:

#### On Linux:
```bash
node ./dist/gencode.js [-c|-m] <callsign>
```

#### On Windows:
```powershell
node .\dist\gencode.js [-c|-m] <callsign>
```

**Options:**
- `-c` or `-u`: Force uppercase callsign (recommended for amateur radio callsigns).
- `-m` or `-l`: Force lowercase callsign.

**Example:**
```bash
node ./dist/gencode.js -c F4XXX
```
Output:
```text
Login/Passcode generator for XLXMOND v2.0
Copyright (c) 2023-26 Jean-Michel Cohen, F4JDN <f4jdn@outlook.fr>

F4XXX passcode is 48291
```

Users navigate to the dashboard, enter their callsign and the generated numeric passcode. Passcodes are calculated statelessly using CRC16 hashing with your secret key — no database storage is needed.

### 3. Administrator Access

To log in with administrator privileges, open:
```text
http://<server-ip>:7779?admin
```
*(The admin username defaults to `admin`, configurable via `admin_user__` in `src/config.ts`)*.

---

## Configuration Reference (`src/config.ts`)

| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `XLXD_IP` | `string` | `'YOUR SERVER IP'` | IP address of your XLX reflector |
| `XLXD_PORTJSON` | `number` | `10001` | XLXD UDP JSON reporting socket |
| `__localhost__` | `string` | `'0.0.0.0'` | Bind address (`0.0.0.0` for all interfaces) |
| `__system_name__` | `string` | `"XLXMOND for XLX"` | System name displayed in header |
| `__monitor_webserver_port__` | `number` | `7779` | Dashboard HTTP web server port |
| `__socketServerPort__` | `number` | `8003` | WebSocket streaming server port |
| `__frequency__` | `number` | `10` | Update frequency push in seconds |
| `__displayLines__` | `number` | `10` | Number of rows shown in heard users table |
| `__theme__` | `string` | `"light_theme"` | Default theme (`"light_theme"` or `"dark_theme"`) |
| `__mod_filter__` | `string` | `""` | Comma-separated module letters to exclude (e.g. `"A,B"`) |
| `__mod_order__` | `string` | `"E,F,H,T,Y,..."` | Custom display order of modules |
| `__mod_names__` | `string` | `'{ ... }'` | JSON string mapping module letters to custom names |
| `__mod_colors__` | `string` | `'{ ... }'` | JSON string mapping module letters to hex colors |
| `__web_auth__` | `boolean` | `false` | Enable/disable user passcode authentication |
| `__web_secret_key__` | `string` | `"SECRET_KEY"` | Salt key used to generate user passcodes |
| `__xlxdlog_file__` | `string` | `'/var/log/xlxd.xml'`| Path to XLXD XML log file |
| `__file_reload__` | `number` | `7` | Days before redownloading RadioID user data |

---

## Project Structure

```text
xlxmond/
├── assets/             # Auto-downloaded RadioID users & reflector list
├── css/                # Dashboard stylesheets & themes
├── dist/               # Transpiled JavaScript production output (npm run build)
├── images/             # Status icons, flags, logos, audio indicators
├── log/                # Application logs and fallback xml/json snapshots
├── pages/              # HTML templates (index, buttonbar, reflectors, etc.)
├── scripts/            # Client-side JavaScript libraries
├── src/                # TypeScript source files
│   ├── config.ts       # Active user configuration (created from sample)
│   ├── config_sample.txt
│   ├── gencode.ts      # Passcode generation utility
│   ├── monitor.ts      # Core microservice (HTTP, WebSocket & UDP engine)
│   └── ...
├── package.json        # Dependencies and build scripts
├── tsconfig.json       # TypeScript compiler settings
└── README.md
```

---

## Troubleshooting & FAQ

### 1. First run takes a long time or seems stuck
XLXMonD automatically downloads the worldwide DMR/RadioID user database (`subscriber_ids.json`, ~80MB) and the XLX reflector list (`reflectorlist.xml`) on the first boot. Please allow 1–3 minutes to complete.

### 2. Changes in `src/config.ts` have no effect
You must rebuild after editing configuration:
```bash
npm run build
```
Then restart the service or process.

### 3. Port permission errors (`EACCES`)
Ports below 1024 require elevated (root/Administrator) privileges. By default, XLXMonD uses ports `7779` and `8003`, which do not require root access. If you change ports to `80` or `443`, run as root or set up a reverse proxy like Nginx or Caddy.

### 4. WebSocket error or dashboard disconnected
- Verify that port `8003` TCP is open in your firewall.
- If using an Nginx/Apache reverse proxy in front of XLXMonD, ensure WebSocket proxy headers are configured (`Upgrade $http_upgrade`, `Connection "upgrade"`).

---

## License

Copyright (C) 2021-2026 Jean-Michel Cohen, F4JDN <f4jdn@outlook.fr>

This program is free software; you can redistribute it and/or modify it under the terms of the **GNU General Public License (GPLv3)** as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.html) for details.
