# ==============================================================================
# Makefile for TelegramBypass
# ==============================================================================

# 支持 iOS 14.0 - 17.x
TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e

# Rootless / Dopamine / Palera1n 支持配置
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = TelegramBypass

TelegramBypass_FILES = Tweak.x
TelegramBypass_CFLAGS = -fobjc-arc -Wno-unused-variable -Wno-unused-function
TelegramBypass_FRAMEWORKS = Foundation UIKit Security
TelegramBypass_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 Telegram" || true
