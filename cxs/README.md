# CXS

1) Install rust and rustup (https://www.rust-lang.org/install.html).
2) Install libindy (https://repo.evernym.com/libindy/).
3) Clone this repo to your local machine.
4) From the local repository run the following commands to verify everything works:
    ```
    $ cargo build
    $ cargo test
    ```
5) Currently developers are using intellij for IDE development (https://www.jetbrains.com/idea/download/) with the rust plugin (https://plugins.jetbrains.com/plugin/8182-rust).

"Everything is awesome when you're part of a team!" #TeamOneDirection

# Debians and Artifacts

**`libcxs_<ver>_amd.deb`**
- a debian that will install the .so library into /usr/lib, update `ldconfig`, and install provision script to `/usr/share/libcxs/`.
- Published to https://repo.corp.evernym.com/deb/pool/main/libc/libcxs/

**`cxs_<ver>.deb`**
- an unintelligent debian package that puts the nodejs package contents into a global node_modules location.

**`cxs<ver>.tgz`**
- target for the `$npm install cxs<ver>.tgz`

**`libcxs.tar.gz`**
- simple archive of libcxs.so and provision python script.