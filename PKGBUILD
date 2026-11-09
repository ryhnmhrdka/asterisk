# Maintainer: Rosemary <rosemary@kartikacyber.local>
pkgname=constellation-bin
pkgver=0.1.0
pkgrel=1
pkgdesc="Autonomous Pre-Production Code Defense & Security Audit Harness (TUI based on Ratatui & Rataflow)"
arch=('x86_64')
url="https://github.com/rosemary/constellation"
license=('MIT')
depends=('gcc-libs')
makedepends=('cargo' 'rust')
provides=('constellation' 'kartikacyber')
conflicts=('constellation' 'kartikacyber')

build() {
  cd "$srcdir/constellation" || cd "$startdir"
  cargo build --release --locked
}

package() {
  cd "$srcdir/constellation" || cd "$startdir"
  install -Dm755 "target/release/constellation" "$pkgdir/usr/bin/constellation"
  ln -s /usr/bin/constellation "$pkgdir/usr/bin/kartikacyber"
  install -Dm644 "README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
