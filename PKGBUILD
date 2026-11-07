# Maintainer: Rosemary <rosemary@kartikacyber.local>
pkgname=kartikacyber-bin
pkgver=0.1.0
pkgrel=1
pkgdesc="Autonomous Pre-Production Code Defense & Security Audit Harness (TUI based on Ratatui & Rataflow)"
arch=('x86_64')
url="https://github.com/rosemary/kartikacyber"
license=('MIT')
depends=('gcc-libs')
makedepends=('cargo' 'rust')
provides=('kartikacyber')
conflicts=('kartikacyber')

build() {
  cd "$srcdir/kartikacyber" || cd "$startdir"
  cargo build --release --locked
}

package() {
  cd "$srcdir/kartikacyber" || cd "$startdir"
  install -Dm755 "target/release/kartikacyber" "$pkgdir/usr/bin/kartikacyber"
  install -Dm644 "README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}

