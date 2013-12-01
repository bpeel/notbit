bin_PROGRAMS = notbit

AM_CPPFLAGS = \
	$(LIBCRYPTO_CFLAGS) \
	$(NOTBIT_EXTRA_CFLAGS) \
	$(NULL)

notbit_SOURCES = \
	ntb-buffer.c \
	ntb-buffer.h \
	ntb-error.c \
	ntb-error.h \
	ntb-list.c \
	ntb-list.h \
	ntb-log.c \
	ntb-log.h \
	ntb-main-context.c \
	ntb-main-context.h \
	ntb-netaddress.c \
	ntb-netaddress.h \
	ntb-proto.c \
	ntb-proto.h \
	ntb-slab.c \
	ntb-slab.h \
	ntb-slice.c \
	ntb-slice.h \
	ntb-util.c \
	ntb-util.h \
	main.c \
	$(NULL)

notbit_LDFLAGS = \
	$(LIBCRYPTO_LIBS) \
	-pthread \
	$(NULL)
