CC=gcc
CXX=g++
SRCHOME=../src
CFLAGS=-g -I$(SRCHOME)/include -g -O2
LIBNDPI=$(SRCHOME)/lib/libndpi.a
LDFLAGS=$(LIBNDPI) -lpcap -lpthread -lm 
HEADERS=intrusion_detection.h reader_util.h $(SRCHOME)/include/ndpi_api.h \
        $(SRCHOME)/include/ndpi_typedefs.h $(SRCHOME)/include/ndpi_protocol_ids.h
OBJS=ndpiReader.o reader_util.o intrusion_detection.o
PREFIX?=/usr/local

all: ndpiReader 

ndpiReader: $(OBJS) $(LIBNDPI)
	$(CXX) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c $(HEADERS) Makefile
	$(CC) $(CFLAGS) -c $< -o $@

install:
	mkdir -p $(DESTDIR)$(PREFIX)/bin/
	mkdir -p $(DESTDIR)$(PREFIX)/share/ndpi
	cp ndpiReader $(DESTDIR)$(PREFIX)/bin/
	cp protos.txt $(DESTDIR)$(PREFIX)/share/ndpi/ndpiProtos.txt
	cp mining_hosts.txt $(DESTDIR)$(PREFIX)/share/ndpi/ndpiCustomCategory.txt
	[ -f build/app/ndpiReader.dpdk ] && cp build/app/ndpiReader.dpdk $(DESTDIR)$(PREFIX)/bin/ || true
	[ -f ndpiReader.dpdk ] && cp ndpiReader.dpdk $(DESTDIR)$(PREFIX)/bin/ || true

dpdk:
	make -f Makefile.dpdk

check:
	 cppcheck --template='{file}:{line}:{severity}:{message}' --quiet --enable=all --force -I$(SRCHOME)/include *.c

clean:
	/bin/rm -f *.o ndpiReader ndpiReader.dpdk
	/bin/rm -f .*.dpdk.cmd .*.o.cmd *.dpdk.map .*.o.d
	/bin/rm -f _install _postbuild _postinstall _preinstall
	/bin/rm -rf build

distclean: clean
	/bin/rm -f Makefile.dpdk
	/bin/rm -f Makefile
