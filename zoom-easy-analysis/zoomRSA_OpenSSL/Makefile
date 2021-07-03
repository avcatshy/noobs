CC=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang
# ARCH_FLAGS= -arch arm64
# SYSROOT= /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk
SYSROOT = /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/
INCLUDE_DIR  := include
INCLUDES     := $(INCLUDE_DIR)
FRAMEWORK = -framework Foundation
TARGET = RSA
SOURCE = main.mm

bin:$(SOURCE)
	$(CC) -I$(INCLUDES) -L lib/  ./lib/libssl.a ./lib/libcrypto.a  -isysroot $(SYSROOT)   $(FRAMEWORD) $(SOURCE) -o $(TARGET) 
clean:
	rm $(TARGET)