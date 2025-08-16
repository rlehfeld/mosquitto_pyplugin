PYTHON ?= pypy3.9
PYBIN := $(shell readlink -m $(shell which ${PYTHON}))
ifdef VIRTUAL_ENV
  DESTDIR ?= ${VIRTUAL_ENV}
else
  DESTDIR ?= /usr
endif
LIBDESTDIR ?= ${DESTDIR}/lib64
PYDESTDIR ?= ${LIBDESTDIR}/$(shell basename ${PYBIN})

export PYHOME

all: libmosquitto_pyplugin.so

libmosquitto_pyplugin.so: mosquitto_pyplugin_generator.py mosquitto_pyplugin_export.h mosquitto_pyplugin_impl.c
	$(PYBIN) $<

${LIBDESTDIR}/%.so: %.so
	mkdir -p $(@D)
	install -s -m 755 $< $(@D)

${PYDESTDIR}/%.py: %.py
	mkdir -p $(@D)
	install -m 755 $< $(@D)

install: ${LIBDESTDIR}/libmosquitto_pyplugin.so ${PYDESTDIR}/mosquitto_pyplugin.py

clean:
	rm -f *.so *.o _mosquitto_pyplugin.c

.PHONY: all clean
