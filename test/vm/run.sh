#!/bin/bash
# Build myfw and run test/e2e.sh inside a throw-away QEMU VM.
#
# The VM boots a stock Ubuntu kernel straight into an initramfs (busybox +
# iproute2 + the firewall), so nothing on the host network is touched and a
# kernel bug can only crash the VM.
#
#   sudo ./test/vm/run.sh                 # uses the newest kernel with headers
#   sudo KVER=6.8.0-147-generic ./test/vm/run.sh
#
# Needs: qemu-system-x86, busybox-static, cpio, zstd, iproute2, util-linux,
#        linux-image-$KVER and linux-headers-$KVER (apt install ...).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${OUT:-$ROOT/test/vm/out}

if [[ -z "${KVER:-}" ]]; then
	for d in $(ls -d /lib/modules/*/build 2>/dev/null | sort -V -r); do
		v=$(basename "$(dirname "$d")")
		[[ -e /boot/vmlinuz-$v ]] && { KVER=$v; break; }
	done
fi
[[ -n "${KVER:-}" ]] || { echo "no kernel with headers found (apt install linux-image-generic linux-headers-generic)"; exit 1; }
KIMG=/boot/vmlinuz-$KVER
KDIR=/lib/modules/$KVER/build
echo ">>> kernel $KVER"

# ---- build against that kernel ------------------------------------------
make -s -C "$ROOT/kernel_mod" KDIR="$KDIR" >/dev/null
gcc -O2 -static -Wall -I"$ROOT/include" -o "$OUT.uapp" "$ROOT"/cmd/{main,nl,util}.c
gcc -O2 -static -Wall -o "$OUT.fwtest" "$ROOT/test/fwtest.c"

# ---- initramfs -----------------------------------------------------------
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
R=$W/root
mkdir -p "$R"/{bin,sbin,usr/bin,usr/local/sbin,lib,lib64,proc,sys,dev,tmp,run,fw,etc,var}
ln -s /run "$R/var/run"
cp "$(command -v busybox)" "$R/bin/busybox"

copy_with_libs() {   # copy a dynamic binary plus the libraries it needs
	cp "$1" "$R$2"
	ldd "$1" | grep -o '/[^ ]*' | while read -r lib; do
		mkdir -p "$R$(dirname "$lib")"
		cp -L "$lib" "$R$lib"
	done
}
copy_with_libs "$(command -v ip)" /usr/local/sbin/ip   # busybox ip lacks netns
copy_with_libs "$(command -v setpriv)" /usr/bin/setpriv

VETH=$(find "/lib/modules/$KVER" -name 'veth.ko*' | head -1)
case "$VETH" in
	*.zst) zstd -qdc "$VETH" > "$R/fw/veth.ko" ;;
	*.xz)  xz -dc "$VETH" > "$R/fw/veth.ko" ;;
	*)     cp "$VETH" "$R/fw/veth.ko" ;;
esac
cp "$ROOT/kernel_mod/myfw.ko" "$R/fw/"
cp "$OUT.uapp" "$R/fw/uapp"
cp "$OUT.fwtest" "$R/fw/fwtest"
cp "$ROOT/test/e2e.sh" "$R/fw/e2e.sh"

cat > "$R/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/usr/local/sbin:/bin:/sbin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmp /tmp
mount -t tmpfs run /run
hostname fwvm
insmod /fw/veth.ko
echo "E2E_BEGIN"
sh /fw/e2e.sh
echo "E2E_EXIT=$?"
poweroff -f
EOF
chmod +x "$R/init" "$R/fw/e2e.sh"
(cd "$R" && find . | cpio -o -H newc --quiet | gzip -1) > "$W/initramfs.gz"

# ---- boot ----------------------------------------------------------------
ACCEL=tcg
[[ -w /dev/kvm ]] && ACCEL=kvm
LOG=$OUT.log
echo ">>> booting VM ($ACCEL), log: $LOG"
timeout 1200 qemu-system-x86_64 -accel $ACCEL -cpu max -smp 2 -m 1024 \
	-nographic -no-reboot -kernel "$KIMG" -initrd "$W/initramfs.gz" \
	-append "console=ttyS0 quiet loglevel=3 panic=-1" \
	| tr -d '\r' | sed -u -n '/E2E_BEGIN/,$p' | tee "$LOG"

grep -q '^E2E_EXIT=0' "$LOG"
