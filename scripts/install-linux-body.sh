# shellcheck shell=sh
# Prefixed by the publisher with public repository locations and immutable key pins.
set -eu
umask 022
die() { printf 'LASA setup: %s\n' "$*" >&2; exit 1; }
run_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }
if ! command -v uname >/dev/null || [ "$(uname -s)" != Linux ]; then die 'Linux is required; this installs no native macOS/Windows scanner.'; fi
case "$(uname -m)" in x86_64|amd64) native_arch=x86_64;; aarch64|arm64) native_arch=aarch64;; *) die 'Only Linux AMD64 and ARM64 packages are published.';; esac
manager=
# Prefer the OS family over unrelated package tools installed by a developer.
os_ids=$(awk -F= '$1=="ID" || $1=="ID_LIKE" {gsub(/["\047]/,"",$2); printf "%s ",$2}' /etc/os-release 2>/dev/null || true)
for os_id in $os_ids; do
  case "$os_id" in
    alpine) manager=apk;;
    opensuse*|suse|sles) manager=zypper;;
    fedora|rhel|centos|rocky|almalinux|ol|amzn)
      if command -v dnf >/dev/null; then manager=dnf; else manager=yum; fi;;
    arch|archarm|manjaro|endeavouros) manager=pacman;;
    debian|ubuntu|linuxmint|pop|kali|raspbian|elementary) manager=apt-get;;
  esac
  [ -z "$manager" ] || break
done
if [ -n "$manager" ]; then
  command -v "$manager" >/dev/null || die "The OS family requires $manager, but that package manager is unavailable."
else
  count=0
  for candidate in apk zypper dnf yum pacman apt-get; do
    if command -v "$candidate" >/dev/null; then manager=$candidate; count=$((count + 1)); fi
  done
  [ "$count" -le 1 ] || die 'Unrecognized OS family and multiple package managers; refusing to guess which system database to change.'
fi
[ -n "$manager" ] || die 'Supported package managers: apt-get, dnf, yum, zypper, pacman, apk. Use the verified archive on other systems.'
case "${1:-}" in
  --detect) printf '%s %s\n' "$manager" "$native_arch"; exit 0;;
  '') ;;
  *) die 'Usage: sh install.sh [--detect]';;
esac
[ "$#" -le 1 ] || die 'Unexpected arguments.'
if [ "$(id -u)" != 0 ]; then command -v sudo >/dev/null || die 'Run as root or provide sudo for repository/package installation.'; fi
printf 'Setting up LASA using %s for %s. Package installation starts no scanner or service.\n' "$manager" "$native_arch"
case "$manager" in
  apt-get)
    run_root apt-get update -o APT::Update::Error-Mode=any
    run_root apt-get install -y ca-certificates curl gnupg
    ;;
  dnf|yum) run_root "$manager" install -y ca-certificates curl gnupg2;;
  zypper) run_root zypper --non-interactive install --no-recommends ca-certificates curl gpg2;;
  pacman)
    # Never refresh a rolling-release database and then perform a partial upgrade.
    printf 'Arch setup performs a full system upgrade to preserve rolling-release package compatibility.\n'
    run_root pacman -Syu --needed --noconfirm ca-certificates curl gnupg
    ;;
  apk) run_root apk add --no-cache ca-certificates curl openssl;;
esac
temp=$(mktemp -d)
stage='retrieving and verifying repository trust data'
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -rf "$temp"
  if [ "$status" != 0 ]; then printf 'LASA setup failed during %s (exit %s). Resolve the preceding package-manager/network/permission diagnostic and rerun; no scan was started.\n' "$stage" "$status" >&2; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
fetch() {
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 --max-time 120 --max-filesize 8388608 "$1" -o "$2"
}
write_config() {
  # Do not silently replace another repository/key using the same local name.
  if [ -e "$2" ] && ! cmp -s "$1" "$2"; then die "Conflicting existing file: $2. It was not overwritten; review its repository/key ownership."; fi
  run_root install -m 0644 "$1" "$2"
}
if [ "$manager" = apt-get ]; then
  fetch "$LASA_BASE_URL/install-apt.sh" "$temp/install-apt.sh"
  actual=$(sha256sum "$temp/install-apt.sh" | awk '{print $1}')
  [ "$actual" = "$LASA_APT_INSTALLER_SHA256" ] || die 'APT setup script does not match the published dispatcher; retry after publication caches settle.'
  bash "$temp/install-apt.sh"
  exit 0
fi
if [ "$manager" = apk ]; then
  fetch "$LASA_BASE_URL/apk/lasa.rsa.pub" "$temp/lasa.rsa.pub"
  actual=$(sha256sum "$temp/lasa.rsa.pub" | awk '{print $1}')
  [ "$actual" = "$LASA_APK_PUBLIC_KEY_SHA256" ] || die 'Alpine public-key hash differs from the pinned trust key; nothing was trusted.'
  run_root install -d -m 0755 /etc/apk/keys
  write_config "$temp/lasa.rsa.pub" /etc/apk/keys/lasa.rsa.pub
  repository="$LASA_BASE_URL/apk"
  if ! grep -Fqx "$repository" /etc/apk/repositories; then
    # Append only the exact LASA entry, retaining the distribution's repositories.
    printf '\n%s\n' "$repository" | run_root tee -a /etc/apk/repositories >/dev/null
  fi
  stage='refreshing the signed Alpine repository and installing LASA'
  run_root apk update
  run_root apk add lasa
else
  fetch "$LASA_BASE_URL/apt/lasa-signing-key.asc" "$temp/openpgp.asc"
  gpg_tool=gpg
  command -v "$gpg_tool" >/dev/null || gpg_tool=gpg2
  mkdir -m 0700 "$temp/gnupg"
  fingerprints=$("$gpg_tool" --batch --homedir "$temp/gnupg" --show-keys --with-colons "$temp/openpgp.asc" | awk -F: '$1=="pub"{primary=1;next} primary && $1=="fpr"{print $10;primary=0}')
  [ "$fingerprints" = "$LASA_OPENPGP_FINGERPRINT" ] || die 'OpenPGP key differs from the pinned primary fingerprint; nothing was trusted.'
  if [ "$manager" = pacman ]; then
    run_root pacman-key --init
    run_root pacman-key --add "$temp/openpgp.asc"
    run_root pacman-key --lsign-key "$LASA_OPENPGP_FINGERPRINT"
    run_root install -d -m 0755 /etc/pacman.d
    printf '[lasa]\nSigLevel = Required DatabaseRequired\nServer = %s/arch/%s\n' "$LASA_BASE_URL" "$native_arch" > "$temp/lasa.conf"
    # Refuse a separately configured [lasa] section instead of shadowing it.
    if grep -Eq '^[[:space:]]*\[lasa\][[:space:]]*$' /etc/pacman.conf; then die 'An existing [lasa] section is configured directly in /etc/pacman.conf; review it before setup.'; fi
    write_config "$temp/lasa.conf" /etc/pacman.d/lasa.conf
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]*=[[:space:]]*/etc/pacman.d/lasa.conf[[:space:]]*$' /etc/pacman.conf; then
      printf '\nInclude = /etc/pacman.d/lasa.conf\n' | run_root tee -a /etc/pacman.conf >/dev/null
    fi
    stage='refreshing signed Pacman databases and installing LASA with the required full upgrade'
    run_root pacman -Syu --needed --noconfirm lasa
  else
    run_root install -d -m 0755 /etc/pki/rpm-gpg
    write_config "$temp/openpgp.asc" /etc/pki/rpm-gpg/RPM-GPG-KEY-lasa
    run_root rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-lasa
    printf '[lasa]\nname=LASA\nbaseurl=%s/rpm/%s\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-lasa\n' "$LASA_BASE_URL" "$native_arch" > "$temp/lasa.repo"
    stage="refreshing the signed RPM repository and installing LASA using $manager"
    if [ "$manager" = zypper ]; then
      printf 'autorefresh=1\n' >> "$temp/lasa.repo"
      run_root install -d -m 0755 /etc/zypp/repos.d
      write_config "$temp/lasa.repo" /etc/zypp/repos.d/lasa.repo
      run_root zypper --non-interactive --gpg-auto-import-keys refresh lasa
      run_root zypper --non-interactive install --from lasa lasa
    else
      run_root install -d -m 0755 /etc/yum.repos.d
      write_config "$temp/lasa.repo" /etc/yum.repos.d/lasa.repo
      run_root "$manager" install -y lasa
    fi
  fi
fi
lasa version
printf 'LASA installed. Run lasa doctor, then lasa scan. Future updates use your normal package manager.\n'
