PYTHON ?= pypy3.9
DESTDIR ?= /usr
LIBDESTDIR ?= ${DESTDIR}/lib64
PYDESTDIR ?= ${LIBDESTDIR}/${PYTHON}

all: mosquitto_pyplugin.so

mosquitto_pyplugin.so: mosquitto_pyplugin_generator.py mosquitto_pyplugin_export.h mosquitto_pyplugin_impl.c
	$(PYTHON) $<

${LIBDESTDIR}/%.so: %.so
	mkdir -p $(@D)
	install -s -m 755 $< $(@D)

${PYDESTDIR}/%.py: %.py
	mkdir -p $(@D)
	install -m 755 $< $(@D)

install: ${LIBDESTDIR}/mosquitto_pyplugin.so ${PYDESTDIR}/mosquitto_pyplugin.py

clean:
	rm -f *.so *.o mosquitto_pyplugin.c

.PHONY: all clean
