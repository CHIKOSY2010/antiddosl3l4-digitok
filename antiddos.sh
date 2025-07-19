#!/bin/bash

# === Cek root ===
if [ "$EUID" -ne 0 ]; then
  echo -e "\033[1;31m❌ Harus dijalankan sebagai root!\033[0m"
  exit 1
fi

# === ASCII Banner ===
echo -e "\033[1;36m"
cat << "EOF"

     _          _   _   ____  ____       ____    _     _____   ___    _  _   
    / \   _ __ | |_(_) |  _ \|  _ \  ___/ ___|  | |   |___ /  / / |  | || |  
   / _ \ | '_ \| __| | | | | | | | |/ _ \___ \  | |     |_ \ / /| |  | || |_ 
  / ___ \| | | | |_| | | |_| | |_| | (_) |__) | | |___ ___) / / | |__|__   _|
 /_/   \_\_| |_|\__|_|_|____/|____/ \___/____/  |_____|____/_/  |_____| |_|  
 | |__  _   _  |  _ \(_) __ _(_) |_ ___ | | __                               
 | '_ \| | | | | | | | |/ _` | | __/ _ \| |/ /                               
 | |_) | |_| | | |_| | | (_| | | || (_) |   < _                              
 |_.__/ \__, | |____/|_|\__, |_|\__\___/|_|\_(_)                             
        |___/           |___/                                                 

EOF
echo -e "\033[0m"

echo "🛡️ Anti-DDoS L3/L4 — Autoinstaller (Node.js Edition)"
echo "📌 Silakan masukkan webhook Discord untuk notifikasi."
read -p $'\n🔗 Masukkan Discord Webhook URL: ' DISCORD_WEBHOOK

# === Validasi Webhook Sederhana ===
if [[ -z "$DISCORD_WEBHOOK" || ! "$DISCORD_WEBHOOK" =~ ^https://discord\.com/api/webhooks/[a-zA-Z0-9]+/[a-zA-Z0-9_-]+$ ]]; then
  echo -e "\033[1;31m❌ Webhook tidak valid. Pastikan menggunakan format yang benar.\033[0m"
  exit 1
fi

# === Variabel Konfigurasi ===
LOG_FILE="/var/log/antiddos.log"
SCRIPT_PATH="/root/antiddosl3l4_final.js"
SERVICE_PATH="/etc/systemd/system/antiddosl3l4.service"
NFTABLES_SCRIPT="/etc/nftables/anti-ddos.nft"
IPSET_INIT="/etc/nftables/ipset-init.sh"

# === Instalasi Dependensi ===
echo -e "\n🔧 Menginstal dependensi..."
apt update && apt install -y curl nftables ipset build-essential nodejs npm

# === Instalasi axios untuk Node.js ===
npm install -g axios

# === Buat Folder Jika Belum Ada ===
mkdir -p /etc/nftables/

# === Buat Node.js Script ===
echo -e "\n📄 Membuat Node.js script..."
cat > "$SCRIPT_PATH" <<EOF
#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const axios = require('axios');

const DISCORD_WEBHOOK = "$DISCORD_WEBHOOK";
const BLOCK_DURATION = 3600;
const MAX_BLOCK_PER_MIN = 5;
const LOG_FILE = "$LOG_FILE";

const rateLimit = {};

function log(message) {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    console.log(\`[\${timestamp}] \${message}\`);
}

function sendToDiscord(ip, attackType) {
    const timestamp = new Date().toISOString();
    const message = \`\`[ANTI-DDOS]\` \`\${attackType}\` terdeteksi dari \`\${ip}\`\n\n🕒 Waktu: \${new Date().toLocaleString()}\`;
    const data = {
        embeds: [{
            title: "🚨 Serangan DDoS Terdeteksi",
            description: message,
            color: 15158332,
            footer: { text: "Anti-DDoS Final • Pterodactyl Node" },
            timestamp
        }]
    };

    axios.post(DISCORD_WEBHOOK, data).catch(err => {
        log(\`[ERROR] Gagal kirim ke Discord: \${err.message}\`);
    });
}

function blockIP(ip) {
    if (isBlocked(ip)) return;

    log(\`[BLOKIR] Mem-block IP \${ip}\`);

    try {
        execSync(\`nft add rule inet filter input ip saddr \${ip} drop\`, { stdio: 'ignore' });
        execSync(\`ipset add blocked_ips \${ip} timeout \${BLOCK_DURATION}\`, { stdio: 'ignore' });
    } catch (err) {
        log(\`[ERROR] Gagal block IP \${ip}: \${err.message}\`);
    }

    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    fs.appendFileSync(LOG_FILE, \`\${timestamp} | BLOKIR | \${ip} | Jenis: DDoS\n\`);
    sendToDiscord(ip, "DDoS Attack");
}

function isBlocked(ip) {
    try {
        const output = execSync(\`ipset test blocked_ips \${ip}\`, { stdio: 'pipe' }).toString();
        return output.includes("is in set");
    } catch {
        return false;
    }
}

function extractIP(line) {
    const match = line.match(/SRC=(\d+\.\d+\.\d+\.\d+)/);
    return match ? match[1] : null;
}

function rateLimited(ip) {
    const now = Date.now();
    if (rateLimit[ip]) {
        if (now - rateLimit[ip].time < 60000) {
            rateLimit[ip].count++;
            if (rateLimit[ip].count >= MAX_BLOCK_PER_MIN) {
                rateLimit[ip].count = 0;
                rateLimit[ip].time = now;
                return true;
            }
        } else {
            rateLimit[ip] = { time: now, count: 1 };
        }
    } else {
        rateLimit[ip] = { time: now, count: 1 };
    }
    return false;
}

function monitorKernelLogs() {
    log("[INFO] Menjalankan Anti-DDoS L3/L4 Final Edition...");
    const { spawn } = require('child_process');
    const journal = spawn('journalctl', ['-kf', '_TRANSPORT=kernel']);

    journal.stdout.on('data', (data) => {
        data.toString().split('\n').forEach(line => {
            const ip = extractIP(line);
            if (ip && /icmp-flood|syn-flood|udp-flood/.test(line)) {
                log(\`[ALERT] Potensi DDoS dari IP: \${ip}\`);
                if (!rateLimited(ip)) {
                    blockIP(ip);
                } else {
                    log(\`[RATE-LIMIT] IP \${ip} dilewati karena melebihi limit blokir per menit.\`);
                }
            }
        });
    });

    journal.stderr.on('data', (data) => log(\`[ERROR] journalctl stderr: \${data}\`));
    journal.on('close', code => log(\`[INFO] Proses journalctl ditutup dengan kode: \${code}\`));
}

monitorKernelLogs();
EOF

chmod +x "$SCRIPT_PATH"
chown root:root "$SCRIPT_PATH"

# === Buat systemd service ===
echo -e "\n🔧 Membuat systemd service..."
cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=Anti-DDoS Final Edition for Pterodactyl Game Hosting
After=network.target

[Service]
ExecStart=/usr/bin/node $SCRIPT_PATH
Restart=on-failure
RestartSec=5s
User=root

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_PATH"
systemctl daemon-reload

# === Buat nftables rules ===
echo -e "\n🧱 Membuat nftables rules..."
cat > "$NFTABLES_SCRIPT" <<'EOF'
#!/usr/bin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
        ip protocol icmp limit rate 10/second burst 20 packets counter log prefix "icmp-flood: " drop
        tcp flags & (syn) == syn ct state new limit rate 50/second burst 100 packets counter log prefix "syn-flood: " drop
        udp dport {domain, bootps} limit rate 100/second burst 200 packets counter log prefix "udp-flood: " drop
    }
}
EOF

chmod +x "$NFTABLES_SCRIPT"
$NFTABLES_SCRIPT

# === Buat ipset init ===
echo -e "\n🔁 Membuat ipset init script..."
cat > "$IPSET_INIT" <<'EOF'
#!/bin/bash
ipset create blocked_ips hash:ip timeout 3600 2>/dev/null || ipset flush blocked_ips
nft add rule inet filter input ip saddr @blocked_ips drop 2>/dev/null || true
EOF

chmod +x "$IPSET_INIT"
$IPSET_INIT

touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

echo -e "\n🟢 Mengaktifkan service systemd..."
systemctl enable antiddosl3l4
systemctl start antiddosl3l4

# === Enable dan Restart nftables agar rules persisten
echo -e "\n🔁 Mengaktifkan nftables..."
systemctl enable nftables
systemctl restart nftables

echo -e "\n✅ INSTALASI SELESAI!"
echo -e "📌 Anda bisa menggunakan:"
echo -e "   - tail -f /var/log/antiddos.log => Melihat log aktivitas"
echo -e "   - systemctl status antiddosl3l4 => Cek status service"
echo -e "\n🔔 Webhook Discord sudah otomatis tersimpan!"
