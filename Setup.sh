#!/bin/bash

### CONFIGURE YOUR INTERFACES ###
WAN_INTERFACE="enp8s0"  # Change to match your WAN interface
LAN_INTERFACE="enx00051b85af50"  # Change to match your LAN interface
PIHOLE_IP="192.168.1.2"  # Set to your Pi-hole IP (or change as needed)
LAN_SUBNET="192.168.1.0/24"
LAN_GATEWAY="192.168.1.1"

echo "🚀 Setting up Debian Router & Social Media Blocking..."

### 1️⃣ Install Required Packages ###
echo "📦 Installing dependencies..."
sudo apt update
sudo apt install -y iptables ipset dnsutils isc-dhcp-server netfilter-persistent iptables-persistent cron

### 2️⃣ Enable IP Forwarding (Router Mode) ###
echo "🔄 Enabling IP forwarding..."
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

### 3️⃣ Configure DHCP Server ###
echo "📡 Configuring DHCP Server..."
sudo tee /etc/dhcp/dhcpd.conf > /dev/null <<EOF
subnet $LAN_SUBNET netmask 255.255.255.0 {
    range 192.168.1.100 192.168.1.200;
    option routers $LAN_GATEWAY;
    option domain-name-servers $PIHOLE_IP, 8.8.8.8;
    option broadcast-address 192.168.1.255;
    default-lease-time 600;
    max-lease-time 7200;
}
EOF
echo "INTERFACESv4=\"$LAN_INTERFACE\"" | sudo tee /etc/default/isc-dhcp-server
sudo systemctl restart isc-dhcp-server

### 4️⃣ Configure NAT (Internet Sharing) ###
echo "🌐 Setting up NAT..."
sudo iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
sudo iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -j ACCEPT
sudo iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

### 5️⃣ Setup Social Media Blocking Scripts ###
echo "🛑 Creating Social Media Blocking Scripts..."

# Blocklist file
sudo tee /etc/blocked_sites.txt > /dev/null <<EOF
facebook.com
instagram.com
tiktok.com
twitter.com
EOF

# Block Script
sudo tee /usr/local/bin/block_social.sh > /dev/null <<'EOF'
#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "Blocking social media for LAN devices..."

# Check if ipset exists, if not, create it
if ! ipset list socialmedia_ips &>/dev/null; then
    ipset create socialmedia_ips hash:ip
else
    echo "Clearing existing ipset..."
    ipset flush socialmedia_ips
fi

# Resolve domains to IPs and add to ipset
while IFS= read -r site; do
    echo "Resolving $site..."
    for ip in $(dig +short A $site @8.8.8.8 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'); do
        if ! ipset test socialmedia_ips $ip &>/dev/null; then
            echo "Adding $ip to block list"
            ipset add socialmedia_ips $ip
        fi
    done
done < /etc/blocked_sites.txt

# Remove old DROP rule and insert at the top
iptables -D FORWARD -m set --match-set socialmedia_ips dst -j DROP 2>/dev/null
iptables -I FORWARD 1 -m set --match-set socialmedia_ips dst -j DROP

# Save iptables rules
iptables-save > /etc/iptables/rules.v4
echo "Blocking complete."
EOF

# Unblock Script
sudo tee /usr/local/bin/unblock_social.sh > /dev/null <<'EOF'
#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "Unblocking social media for LAN devices..."

# Remove blocking rule
iptables -D FORWARD -m set --match-set socialmedia_ips dst -j DROP 2>/dev/null

# Flush ipset instead of destroying it
ipset flush socialmedia_ips 2>/dev/null

# Save iptables rules
iptables-save > /etc/iptables/rules.v4
echo "Unblocking complete."
EOF

# Refresh Blocklist Script
sudo tee /usr/local/bin/refresh_blocklist.sh > /dev/null <<'EOF'
#!/bin/bash
echo "Refreshing social media blocklist..."
if iptables -C FORWARD -m set --match-set socialmedia_ips dst -j DROP 2>/dev/null; then
    echo "Blocking is active. Refreshing blocklist..."
    ipset flush socialmedia_ips
    while IFS= read -r site; do
        for ip in $(dig +short A $site @8.8.8.8 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'); do
            ipset add socialmedia_ips $ip
        done
    done < /etc/blocked_sites.txt
    echo "Blocklist refreshed."
else
    echo "Blocking is not active. Skipping refresh."
fi
EOF

# Make scripts executable
sudo chmod +x /usr/local/bin/block_social.sh /usr/local/bin/unblock_social.sh /usr/local/bin/refresh_blocklist.sh

### 6️⃣ Setup Cron Jobs for Automated Blocking ###
echo "⏳ Scheduling automatic blocking/unblocking..."
sudo tee /etc/cron.d/timed_block > /dev/null <<EOF
0 23 * * * root /usr/local/bin/block_social.sh   # Block at 11 PM
0 9 * * * root /usr/local/bin/unblock_social.sh  # Unblock at 9 AM
*/10 * * * * root /usr/local/bin/refresh_blocklist.sh  # Refresh every 10 min
EOF
sudo systemctl restart cron

### 7️⃣ Save and Enable iptables Persistence ###
echo "💾 Saving iptables rules..."
sudo iptables-save | sudo tee /etc/iptables/rules.v4
sudo systemctl enable netfilter-persistent
sudo systemctl restart netfilter-persistent

echo "✅ Setup Complete! Your Debian router is now ready."
