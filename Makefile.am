# XXX - this is a massive hack to make autoreconf honour the ACLOCAL_FLAGS
# that jhbuild sets while still retaining build/autotools as the authoritative
# source for m4 macros
ACLOCAL_AMFLAGS = -I build/autotools ${ACLOCAL_FLAGS}

SUBDIRS = \
	doc \
	src \
	build \
	$(NULL)

EXTRA_DIST = \
	autogen.sh \
	NEWS \
	README.md \
	$(NULL)
