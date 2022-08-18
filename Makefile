PYTHON ?= pypy3.9
DESTDIR ?= /usr

all: mosquitto_plugin.so

mosquitto_plugin.so: mosquitto_plugin.py mosquitto_plugin_export.h mosquitto_plugin_impl.c
	$(PYTHON) $<

install: mosquitto_plugin.so
	mkdir -p $(DESTDIR)/lib/mosquitto
	install -s -m 755 $< $(DESTDIR)/lib/mosquitto

clean :
	rm -f *.so *.o mosquitto_plugin.c

.PHONY: all clean
