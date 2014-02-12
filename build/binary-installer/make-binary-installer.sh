#!/bin/bash

set -eu

OPENSSL_VERSION=1.0.1f
TOPDIR=$(cd $(dirname "$0")/../.. && pwd)
OPENSSL_TARBALL_BASE=openssl-"$OPENSSL_VERSION".tar.gz
OPENSSL_TARBALL_URL=https://www.openssl.org/source/"$OPENSSL_TARBALL_BASE"
OPENSSL_TARBALL_FILE="$TOPDIR/$OPENSSL_TARBALL_BASE"
OPENSSL_BUILDDIR="$TOPDIR/openssl-$OPENSSL_VERSION"
OPENSSL_KEYID="F295C759"
OPENSSL_PREFIX="${TOPDIR}/openssl-install"
PKGCONFIG_WRAPPER="${TOPDIR}/pkgconfig-wrapper.sh"
NOTBIT_VERSION=`sed -rn -e '1s/AC_INIT\(.*([0-9]+\.[0-9]+)\).*/\1/p' \
                "${TOPDIR}/configure.ac"`
INSTALLER_HEADER="${TOPDIR}/build/binary-installer/installer-header.sh"
INSTALLER_SCRIPT="${TOPDIR}/notbit-${NOTBIT_VERSION}.sh"

cat > "$PKGCONFIG_WRAPPER" <<EOF
export PKG_CONFIG_LIBDIR=$OPENSSL_PREFIX/lib/pkgconfig
exec pkg-config "\$@"
EOF
chmod a+x "$PKGCONFIG_WRAPPER"

if ! test -f "$OPENSSL_TARBALL_FILE"; then
    curl -L "$OPENSSL_TARBALL_URL" > "$OPENSSL_TARBALL_FILE"
    curl -L "${OPENSSL_TARBALL_URL}.asc" > "${OPENSSL_TARBALL_FILE}.asc"
fi

if ! gpg --list-keys "$OPENSSL_KEYID" > /dev/null; then
    set +x
    echo
    echo "The public key used to sign OpenSSL releases is not in your keyring "
    echo "so the tarball can not be verified. You can retrieve by typing: "
    echo
    echo " gpg --recv-keys 0x$OPENSSL_KEYID"
    exit 1
fi

gpg -r "$OPENSSL_KEYID" --verify "${OPENSSL_TARBALL_FILE}"{.asc,}

if test -e "$OPENSSL_BUILDDIR"; then
    rm -rf "$OPENSSL_BUILDDIR"
fi

if test -e "$OPENSSL_PREFIX"; then
    rm -rf "$OPENSSL_PREFIX"
fi
mkdir -p "${OPENSSL_PREFIX}/lib/pkgconfig"

tar -C "$TOPDIR" -zxf "$OPENSSL_TARBALL_FILE"

cd "$OPENSSL_BUILDDIR"

# enabling sha ripemd ec ecdsa ecdh hw cms aes md5
./config \
    no-threads \
    no-zlib \
    no-shared \
    no-idea \
    no-camellia \
    no-seed \
    no-bf \
    no-cast \
    no-des \
    no-rc2 \
    no-rc4 \
    no-rc5 \
    no-md2 \
    no-md4 \
    no-mdc2 \
    no-rsa \
    no-dsa \
    no-dh \
    no-sock \
    no-ssl2 \
    no-ssl3 \
    no-err \
    no-krb5 \
    no-engine \
    no-tlsext \
    no-jpake \
    no-capieng \
    no-dso \
    --prefix="$OPENSSL_PREFIX"

make -j4 build_crypto
make libcrypto.pc

cp -L libcrypto.pc "$OPENSSL_PREFIX/lib/pkgconfig/"
cp -L libcrypto.a "$OPENSSL_PREFIX/lib/"
cp -L -R include "$OPENSSL_PREFIX/"

cd "$TOPDIR"
./configure \
    PKG_CONFIG="$PKGCONFIG_WRAPPER"
make -j4

strip --strip-all "${TOPDIR}/src/notbit"

installer_header_length=`wc -l "$INSTALLER_HEADER".in |
                         sed -r "s/^ *([0-9]+).*/\\1/"`
installer_header_offset=`expr $installer_header_length + 1`

sed s/@INSTALLER_HEADER_OFFSET@/"$installer_header_offset"/g \
    < "$INSTALLER_HEADER".in > "$INSTALLER_HEADER"

tar -C "${TOPDIR}/src" -zcf - notbit{-sendmail,-keygen,} | \
    cat "$INSTALLER_HEADER" - > \
    "$INSTALLER_SCRIPT"

chmod a+x "$INSTALLER_SCRIPT"

rm -f "$INSTALLER_SCRIPT".asc
gpg -a --detach-sign "$INSTALLER_SCRIPT"

echo
echo "The installer is now available at "
echo "$INSTALLER_SCRIPT"
echo "with a signature at"
echo "$INSTALLER_SCRIPT".asc
