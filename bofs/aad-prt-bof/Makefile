CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
CFLAGS = -Os -s -w
STRIP64 = x86_64-w64-mingw32-strip
STRIP86 = i686-w64-mingw32-strip

BOFS = aad_prt

all: dirs $(foreach b,$(BOFS),out64/$(b)64.o out86/$(b)86.o)

dirs:
	@mkdir -p out64 out86

out64/%64.o: %.c
	$(CC64) $(CFLAGS) -c $< -o $@
	$(STRIP64) --strip-unneeded $@

out86/%86.o: %.c
	$(CC86) $(CFLAGS) -c $< -o $@
	$(STRIP86) --strip-unneeded $@

clean:
	rm -rf out64 out86

.PHONY: all dirs clean
