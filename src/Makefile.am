bin_PROGRAMS = \
	notbit \
	notbit-sendmail \
	$(NULL)

noinst_PROGRAMS = dump-store

AM_CPPFLAGS = \
	$(LIBCRYPTO_CFLAGS) \
	$(NOTBIT_EXTRA_CFLAGS) \
	$(NULL)

notbit_SOURCES = \
	ntb-address.c \
	ntb-address.h \
	ntb-base58.c \
	ntb-base58.h \
	ntb-base64.c \
	ntb-base64.h \
	ntb-blob.c \
	ntb-blob.h \
	ntb-buffer.c \
	ntb-buffer.h \
	ntb-connection.c \
	ntb-connection.h \
	ntb-cpus.c \
	ntb-cpus.h \
	ntb-crypto.c \
	ntb-crypto.h \
	ntb-ecc.c \
	ntb-ecc.h \
	ntb-error.c \
	ntb-error.h \
	ntb-file-error.c \
	ntb-file-error.h \
	ntb-hash-table.c \
	ntb-hash-table.h \
	ntb-ipc.c \
	ntb-ipc.h \
	ntb-ipc-proto.h \
	ntb-ipc-sockaddr.c \
	ntb-ipc-sockaddr.h \
	ntb-key.c \
	ntb-key.h \
	ntb-keyring.c \
	ntb-keyring.h \
	ntb-list.c \
	ntb-list.h \
	ntb-load-keys.c \
	ntb-load-keys.h \
	ntb-log.c \
	ntb-log.h \
	ntb-mail-parser.c \
	ntb-mail-parser.h \
	ntb-main-context.c \
	ntb-main-context.h \
	ntb-netaddress.c \
	ntb-netaddress.h \
	ntb-network.c \
	ntb-network.h \
	ntb-parse-addresses.c \
	ntb-parse-addresses.h \
	ntb-parse-content-type.c \
	ntb-parse-content-type.h \
	ntb-pointer-array.h \
	ntb-pow.c \
	ntb-pow.h \
	ntb-proto.c \
	ntb-proto.h \
	ntb-quoted-printable.c \
	ntb-quoted-printable.h \
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

notbit_sendmail_SOURCES = \
	ntb-buffer.c \
	ntb-buffer.h \
	ntb-error.c \
	ntb-error.h \
	ntb-file-error.c \
	ntb-file-error.h \
	ntb-sendmail.c \
	ntb-ipc-proto.h \
	ntb-ipc-sockaddr.c \
	ntb-ipc-sockaddr.h \
	ntb-util.c \
	ntb-util.h \
	$(NULL)

notbit_sendmail_LDFLAGS = \
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
