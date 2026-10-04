# mitmproxy_12.2.3-r1_For_OpenWRT
mitmproxy_12.2.3-r1 complied For OpenWRT 25.12

Source : https://github.com/mitmproxy/mitmproxy


Complie the LUCI mitmproxy APK package :
python3 ./build_luci_apk.py 


Install on OpenWrt:
  scp luci-app-mitmproxy_1.0.0-r1_noarch.apk root@<router-ip>:/tmp/
  ssh root@<router-ip> 'apk add --allow-untrusted /tmp/luci-app-mitmproxy_1.0.0-r1_noarch.apk'
  Then visit http://<router-ip>/cgi-bin/luci/admin/services/mitmproxy
