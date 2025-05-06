LOCALBASE?=	/usr/local

SHLIB_NAME=	nbdkit-disk-plugin.so
SHLIBDIR=	${LOCALBASE}/lib/nbdkit/plugins

SRCS+=		disk.c

CFLAGS+=	-I${LOCALBASE}/include

# TODO
#MAN=	nbdkit-disk-plugin.1

.include <bsd.lib.mk>
