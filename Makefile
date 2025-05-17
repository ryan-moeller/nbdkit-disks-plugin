LOCALBASE?=	/usr/local

SHLIB_NAME=	nbdkit-disks-plugin.so
SHLIBDIR=	${LOCALBASE}/lib/nbdkit/plugins

SRCS+=		disks.c

CFLAGS+=	-I${LOCALBASE}/include
# XXX: pkg install libucl (base ucl is private)
LDFLAGS+=	-L${LOCALBASE}/lib -lucl -lnv

# TODO
#MAN=	nbdkit-disks-plugin.1

.include <bsd.lib.mk>
