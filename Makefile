# pc/       the computer side: make, make install, PKGBUILD
# android/  the app: build.sh (SDK only, no Gradle)
.PHONY: all pc android install uninstall clean
all: pc
pc:
	$(MAKE) -C pc
android:
	android/build.sh
install uninstall:
	$(MAKE) -C pc $@
clean:
	$(MAKE) -C pc clean
	rm -rf android/out
