PYTHON ?= pypy3.9
DESTDIR ?= /usr

all: mosquitto_pyplugin.so

mosquitto_pyplugin.so: mosquitto_pyplugin.py mosquitto_pyplugin_export.h mosquitto_pyplugin_impl.c
	$(PYTHON) $<

install: mosquitto_pyplugin.so
	mkdir -p $(DESTDIR)/lib/mosquitto
	install -s -m 755 $< $(DESTDIR)/lib/mosquitto

clean :
	rm -f *.so *.o mosquitto_pyplugin.c

.PHONY: all clean
