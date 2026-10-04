# mitmproxy_12.2.3-r1_For_OpenWRT
mitmproxy_12.2.3-r1 complied For OpenWRT 25.12

Source : https://github.com/mitmproxy/mitmproxy


Complie the LUCI mitmproxy APK package :
python3 ./build_luci_apk.py 


Install on OpenWrt:
  scp luci-app-mitmproxy_1.0.0-r1_noarch.apk root@<router-ip>:/tmp/
  ssh root@<router-ip> 'apk add --allow-untrusted /tmp/luci-app-mitmproxy_1.0.0-r1_noarch.apk'
  Then visit http://<router-ip>/cgi-bin/luci/admin/services/mitmproxy



============================================================
BUILD SUMMARY
============================================================

  Target:   Marvell Armada 385 (Linksys WRT series)
  Arch:     arm_cortex-a9_vfpv3-d16
  Devices:  Linksys WRT1200AC, Linksys WRT1900AC, Linksys WRT3200ACM, Linksys WRT32X
  APK:      mitmproxy_12.2.3-r1_arm_cortex-a9_vfpv3-d16.apk
  Size:     1.5 MB

  Target:   MediaTek MT7986AV (GL.iNet Flint 2)
  Arch:     aarch64_cortex-a53
  Devices:  GL.iNet GL-MT6000 (Flint 2)
  APK:      mitmproxy_12.2.3-r1_aarch64_cortex-a53.apk
  Size:     1.5 MB

  Target:   MediaTek MT7981BA (GL.iNet Beryl AX)
  Arch:     aarch64_cortex-a53
  Devices:  GL.iNet GL-MT3000 (Beryl AX)
  APK:      mitmproxy_12.2.3-r1_aarch64_cortex-a53.apk
  Size:     1.5 MB

  Target:   MediaTek MT7987AV (GL.iNet Beryl 7)
  Arch:     aarch64_cortex-a53
  Devices:  GL.iNet GL-MT3600BE (Beryl 7)
  APK:      mitmproxy_12.2.3-r1_aarch64_cortex-a53.apk
  Size:     1.5 MB

Installation:
  1. Copy the .apk file to your OpenWrt router
  2. Run: apk add --allow-untrusted ./mitmproxy_*.apk
  3. Edit /etc/config/mitmproxy to configure
  4. Run: /etc/init.d/mitmproxy enable
  5. Run: /etc/init.d/mitmproxy start
============================================================
