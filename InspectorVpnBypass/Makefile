# ==============================================================================
# Makefile for InspectorVpnBypass
# ==============================================================================

# 自动检测 THEOS 安装路径 (优先读取环境变量，默认回退到 ~/theos 或 /opt/theos)
ifndef THEOS
  THEOS := $(HOME)/theos
  ifeq ($(wildcard $(THEOS)/*),)
    THEOS := /opt/theos
  endif
endif

# 支持 iOS 14.0 - 17.x
TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e

# Rootless / Dopamine / Palera1n 支持配置
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = InspectorVpnBypass

InspectorVpnBypass_FILES = Tweak.x
InspectorVpnBypass_CFLAGS = -fobjc-arc -Wno-unused-variable -Wno-unused-function
InspectorVpnBypass_FRAMEWORKS = Foundation UIKit Security
InspectorVpnBypass_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 InspectorVpn" || true
