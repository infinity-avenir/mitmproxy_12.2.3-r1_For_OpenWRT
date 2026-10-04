# SPDX-License-Identifier: MIT
#
# OpenWrt package Makefile for luci-app-mitmproxy
# LuCI web interface for mitmproxy HTTP proxy

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-mitmproxy
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

LUCI_TITLE:=LuCI support for mitmproxy
LUCI_DESCRIPTION:=Web interface to configure, monitor, and manage \
	mitmproxy HTTP proxy directly from your \
	OpenWrt router LuCI interface.
LUCI_DEPENDS:=+mitmproxy +luci-base +luci-compat
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

define Package/$(PKG_NAME)/conffiles
/etc/config/mitmproxy
endef

# call BuildPackage - OpenWrt buildance
$(eval $(call BuildPackage,$(PKG_NAME)))
