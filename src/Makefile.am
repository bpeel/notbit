bin_PROGRAMS = notbit

noinst_PROGRAMS = dump-store

AM_CPPFLAGS = \
	$(LIBCRYPTO_CFLAGS) \
	$(NOTBIT_EXTRA_CFLAGS) \
	$(NULL)

notbit_SOURCES = \
	ntb-blob.c \
	ntb-blob.h \
	ntb-buffer.c \
	ntb-buffer.h \
	ntb-connection.c \
	ntb-connection.h \
	ntb-cpus.c \
	ntb-cpus.h \
	ntb-error.c \
	ntb-error.h \
	ntb-file-error.c \
	ntb-file-error.h \
	ntb-hash-table.c \
	ntb-hash-table.h \
	ntb-list.c \
	ntb-list.h \
	ntb-log.c \
	ntb-log.h \
	ntb-main-context.c \
	ntb-main-context.h \
	ntb-netaddress.c \
	ntb-netaddress.h \
	ntb-network.c \
	ntb-network.h \
	ntb-pow.c \
	ntb-pow.h \
	ntb-proto.c \
	ntb-proto.h \
	ntb-ref-count.h \
	ntb-signal.h \
	ntb-slab.c \
	ntb-slab.h \
	ntb-slice.c \
	ntb-slice.h \
	ntb-socket.c \
	ntb-socket.h \
	ntb-store.c \
	ntb-store.h \
	ntb-util.c \
	ntb-util.h \
	main.c \
	$(NULL)

notbit_LDFLAGS = \
	$(LIBCRYPTO_LIBS) \
	$(NOTBIT_EXTRA_LIBS) \
	-pthread \
	$(NULL)

dump_store_SOURCES = \
	ntb-buffer.c \
	ntb-buffer.h \
	ntb-util.c \
	ntb-util.h \
	dump-store.c \
	$(NULL)

dump_store_LDFLAGS = \
	-pthread \
	$(NULL)
