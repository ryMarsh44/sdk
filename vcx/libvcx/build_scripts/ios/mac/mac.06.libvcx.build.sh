#!/bin/sh

source ./shared.functions.sh

START_DIR=$PWD
WORK_DIR=$START_DIR/../../../../../.macosbuild
mkdir -p $WORK_DIR
WORK_DIR=$(abspath "$WORK_DIR")

INDY_SDK=$WORK_DIR/vcx-indy-sdk
VCX_SDK=$START_DIR/../../../../..
VCX_SDK=$(abspath "$VCX_SDK")

source ./mac.05.libvcx.env.sh
cd ../../..
DEBUG_SYMBOLS="debuginfo"

if [ ! -z "$1" ]; then
    DEBUG_SYMBOLS=$1
fi

if [ "$DEBUG_SYMBOLS" = "nodebug" ]; then
    sed -i .bak 's/debug = true/debug = false/' Cargo.toml
fi

IOS_TARGETS="aarch64-apple-ios,armv7-apple-ios,armv7s-apple-ios,i386-apple-ios,x86_64-apple-ios"
if [ ! -z "$2" ]; then
    IOS_TARGETS=$2
fi

CLEAN_BUILD="cleanbuild"
if [ ! -z "$3" ]; then
    CLEAN_BUILD=$3
fi

if [ "$CLEAN_BUILD" = "cleanbuild" ]; then
   cargo clean
   # cargo update
fi

git log -1 > $WORK_DIR/evernym.vcx-sdk.git.commit.log

export OPENSSL_LIB_DIR_DARWIN=$OPENSSL_LIB_DIR

bkpIFS="$IFS"
IFS=',()][' read -r -a targets <<<"${IOS_TARGETS}"
echo "Building targets: ${targets[@]}"    ##Or printf "%s\n" ${array[@]}
IFS="$bkpIFS"

to_combine=""
for target in ${targets[*]}
do
    if [ "${target}" = "aarch64-apple-ios" ]; then
        target_arch="arm64"
    elif [ "${target}" = "armv7-apple-ios" ]; then
        target_arch="armv7"
    elif [ "${target}" = "armv7s-apple-ios" ]; then
        target_arch="armv7s"
    elif [ "${target}" = "i386-apple-ios" ]; then
        target_arch="i386"
    elif [ "${target}" = "x86_64-apple-ios" ]; then
        target_arch="x86_64"
    fi

    if [ -d $WORK_DIR/libindy/${target_arch} ]; then
        echo "${target_arch} libindy architecture already extracted"
    else
        libtool="/usr/bin/libtool"
        libindy_dir="${WORK_DIR}/libindy"
        mkdir ${WORK_DIR}/libindy/${target_arch}
        lipo -extract $target_arch ${libindy_dir}/libindy.a -o ${libindy_dir}/${target_arch}/libindy.a
        ${libtool} -static ${libindy_dir}/${target_arch}/libindy.a -o ${libindy_dir}/${target_arch}/libindy_libtool.a
        mv ${libindy_dir}/${target_arch}/libindy_libtool.a ${libindy_dir}/${target_arch}/libindy.a
    fi 

    export OPENSSL_LIB_DIR=$WORK_DIR/OpenSSL-for-iPhone/lib/${target_arch}
    export IOS_SODIUM_LIB=$WORK_DIR/libzmq-ios/libsodium-ios/dist/ios/lib/${target_arch}
    export IOS_ZMQ_LIB=$WORK_DIR/libzmq-ios/dist/ios/lib/${target_arch}
    export LIBINDY_DIR=$WORK_DIR/libindy/${target_arch}
    export LIBSOVTOKEN_DIR=$WORK_DIR/libsovtoken-ios/libsovtoken/${target}

    cargo build --release --no-default-features --features "ci sovtoken" --target "${target}"

    to_combine="${to_combine} ./target/${target}/release/libvcx.a"

done
mkdir -p ./target/universal/release
lipo -create $to_combine -o ./target/universal/release/libvcx.a

export OPENSSL_LIB_DIR=$OPENSSL_LIB_DIR_DARWIN