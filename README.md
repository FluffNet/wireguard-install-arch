# wireguard-install (Arch & Fluff Linux fork)

A WireGuard [road-warrior](https://en.wikipedia.org/wiki/Road_warrior_%28computing%29) installer for **Fluff Linux and Arch Linux**, with **NetworkManager-aware routing** and **iptables-nft NAT integration**.

This fork is based on the original project by **Nyr**, adapted to work cleanly on Arch-based systems and environments where NetworkManager is used.

It automates:

- WireGuard installation
- Server + client configuration
- NAT routing for internet-bound VPN traffic
- NetworkManager ignore-rules (prevents routing conflicts)
- Optional userspace WireGuard (BoringTun)
- QR-code client export

---

## Requirements

- Fluff Linux or Arch Linux
- root privileges  
- systemd  
- NetworkManager (likely optional however this was tested with NM in mind)

---

## Installation

Run the installer and follow the prompts:

```bash
wget https://raw.githubusercontent.com/FluffNet/wireguard-install-arch/main/wireguard-install.sh -O wireguard-install.sh
chmod +x wireguard-install.sh
sudo ./wireguard-install.sh
```
## Re-run the script any time to:

- add clients  
- remove clients  
- uninstall WireGuard  

Client configuration files are stored alongside the script and also displayed as QR codes for mobile import.

---

## Why this fork?

The upstream project targets Debian and RHEL-based systems.

This fork:

- uses `pacman`
- supports **Fluff Linux & Arch Linux**
- uses the **nftables iptables backend** (Arch default)
- creates persistent NAT via **systemd**
- avoids interfering with your firewall
- prevents NetworkManager from breaking routes
- keeps the original script flow and simplicity

It is designed to be:

**minimal • predictable • Arch-native**

---


## Defaults

- VPN subnet: `10.7.0.0/24`
- Interface: `wg0`
- IPv4 forwarding enabled
- NAT via systemd-managed `iptables-nft`
- NetworkManager ignores `wg0`

These defaults mirror upstream behaviour while remaining Arch-native.

---

## Credits

Original project by **Nyr**  
<https://github.com/Nyr/wireguard-install>

This fork maintained by **FluffNet LLC**  
<https://github.com/FluffNet>

---
