# SSH & VPN Setup — Remote Access

---

## QUIZ DAY — Sitting in a different lab, SSHing into room 103

> Key is stored in NFS home — works from ANY lab machine automatically.

```bash
# From any lab machine terminal (no key flag needed — ~/.ssh/config handles it):
ssh lab103                          # → connects to 10.16.13.53 (ws15)

# Or by IP (any ws machine in 10.16.13.x range):
ssh apieri01@10.16.13.53

# Once connected — go straight to work:
cd ~/326_quiz3
source ~/.bashrc                    # loads nvm + claude + ROPgadget into PATH
claude                              # launch Claude Code
```

`~/.ssh/lab_key` is already on the NFS home (copied 2026-04-21) — no setup needed on any lab machine.

---

## From personal Windows laptop (remote from home)

---

## Lab machine details

| Item | Value |
|------|-------|
| **Machines** | `103ws1`–`103ws33.in.cs.ucy.ac.cy` — any one works |
| Last known working | `103ws15` = `10.16.13.53` |
| User | `apieri01` |
| Home | `/home/students/cs/2024/apieri01` (NFS-shared across all machines) |
| OS | Rocky Linux 9.6 (Blue Onyx) x86_64 |
| SSH key | `C:\Users\andre\.ssh\lab_key` (passwordless — no password prompt ever) |
| VPN config | `C:\Program Files\OpenVPN\config\CSVPNv4.ovpn` |
| VPN username | `apieri01@ucy.ac.cy` |
| VPN credentials file | `C:\Users\andre\.ssh\vpn_creds.txt` |

All ws machines share the same NFS home directory and the same libc.
Files created on ws15 are instantly visible on ws1, ws33, any other.

---

## One-time setup — save VPN credentials

```powershell
# Run in PowerShell as Administrator — do once, reuse forever:
"apieri01@ucy.ac.cy`nYOUR_PASSWORD_HERE" | Out-File -FilePath "C:\Users\andre\.ssh\vpn_creds.txt" -Encoding ascii
```

---

## VPN connect — one command (PowerShell as Administrator)

```powershell
Stop-Process -Name openvpn -Force -ErrorAction SilentlyContinue; Stop-Process -Name openvpn-gui -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1; Start-Process -FilePath "C:\Program Files\OpenVPN\bin\openvpn.exe" -ArgumentList '--config "C:\Program Files\OpenVPN\config\CSVPNv4.ovpn" --auth-user-pass "C:\Users\andre\.ssh\vpn_creds.txt"' -Verb RunAs -WindowStyle Hidden
```
Wait ~10 seconds, then verify SSH.

---

## SSH test

```powershell
# Try ws15 first:
powershell.exe -Command "ssh -i C:\Users\andre\.ssh\lab_key -o StrictHostKeyChecking=no apieri01@10.16.13.53 'hostname' 2>&1"
# → 103ws15.in.cs.ucy.ac.cy

# If that times out, try any other machine (1–33):
powershell.exe -Command "ssh -i C:\Users\andre\.ssh\lab_key -o StrictHostKeyChecking=no apieri01@103ws1.in.cs.ucy.ac.cy 'hostname' 2>&1"
```

---

## Full session start — copy-paste every time

```powershell
Stop-Process -Name openvpn -Force -ErrorAction SilentlyContinue; Stop-Process -Name openvpn-gui -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1; Start-Process -FilePath "C:\Program Files\OpenVPN\bin\openvpn.exe" -ArgumentList '--config "C:\Program Files\OpenVPN\config\CSVPNv4.ovpn" --auth-user-pass "C:\Users\andre\.ssh\vpn_creds.txt"' -Verb RunAs -WindowStyle Hidden; Start-Sleep -Seconds 10; ssh -i C:\Users\andre\.ssh\lab_key -o StrictHostKeyChecking=no apieri01@10.16.13.53 "hostname"
# → 103ws15.in.cs.ucy.ac.cy  ← only proceed if you see this
```

---

## SSH command template (for running commands remotely)

```powershell
powershell.exe -Command "ssh -i C:\Users\andre\.ssh\lab_key -o StrictHostKeyChecking=no apieri01@10.16.13.53 'COMMAND HERE' 2>&1"
```

---

## Transfer files to lab machine

```powershell
# Copy binaries to lab:
powershell.exe -Command "scp -i C:\Users\andre\.ssh\lab_key 'C:\PATH\TO\bin.1' apieri01@10.16.13.53:/home/students/cs/2024/apieri01/"

# Copy exploit files to lab:
powershell.exe -Command "scp -i C:\Users\andre\.ssh\lab_key exploit.1 exploit.2 exploit.3 apieri01@10.16.13.53:/home/students/cs/2024/apieri01/"
```

---

## WSL notes (Windows Subsystem for Linux)

- Always invoke WSL via PowerShell, not Git Bash — Git Bash mangles paths
- Multi-step commands with pipes/redirects MUST use a script file, not inline `-c '...'`
- Write scripts to `C:\Users\andre\AppData\Local\Temp\` (= `/mnt/c/Users/andre/AppData/Local/Temp/` from WSL)
- Windows path prefix for WSL: `C:\...` → `/mnt/c/...`

```powershell
# Correct way to run a multi-step WSL command:
powershell.exe -Command "wsl bash /mnt/c/Users/andre/AppData/Local/Temp/script.sh"

# Wrong — breaks silently with pipes/redirects:
# wsl bash -c 'objdump -d ./bin | grep something'
```

---

## VPN status check

```powershell
powershell.exe -Command "ipconfig | findstr 10.16"
# Should show an IP in 10.16.19.x range when VPN is connected
```
