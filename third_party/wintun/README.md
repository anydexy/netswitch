# wintun

`wintun.dll` 0.14.1 (amd64) and `LICENSE.txt` from the official archive
https://www.wintun.net/builds/wintun-0.14.1.zip
(SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`), fetched by
`.github/workflows/wintun.yml`.

NetSwitch embeds the DLL unmodified and writes it next to `NetSwitch.exe` for the WARP
(AmneziaWG) tunnel; it is used only through the Wintun API (via amneziawg-go).
