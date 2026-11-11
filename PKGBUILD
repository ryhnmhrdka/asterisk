# Maintainer: Rosemary <rosemary@kartikacyber.local>
pkgname=asterisk-bin
pkgver=0.1.0
pkgrel=1
pkgdesc="Autonomous Pre-Production Code Defense & Security Audit Harness (TUI based on Ratatui & Rataflow)"
arch=('x86_64')
url="https://github.com/ryhnmhrdka/asterisk"
license=('MIT')
depends=('gcc-libs')
makedepends=('cargo' 'rust')
provides=('asterisk')
conflicts=('asterisk')

build() {
  cd "$srcdir/asterisk" || cd "$startdir"
  cargo build --release --locked
}

package() {
  cd "$srcdir/asterisk" || cd "$startdir"
  install -Dm755 "target/release/asterisk" "$pkgdir/usr/bin/asterisk"
  install -Dm644 "README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
