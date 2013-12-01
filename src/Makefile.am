bin_PROGRAMS = notbit

AM_CPPFLAGS = \
	$(LIBCRYPTO_CFLAGS) \
	$(NOTBIT_EXTRA_CFLAGS) \
	$(NULL)

notbit_SOURCES = \
	ntb-error.c \
	ntb-error.h \
	ntb-list.c \
	ntb-list.h \
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
	$(NULL)
