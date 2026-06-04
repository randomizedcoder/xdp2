# Overlay: inject a compliant User-Agent into Nixpkgs'
# fetch-cargo-vendor-util.py so it stops violating crates.io's API
# data-access policy.
#
# === Why this exists ===
#
# Nixpkgs' rustPlatform.fetchCargoVendor is implemented in
# pkgs/build-support/rust/fetch-cargo-vendor.nix and uses a Python
# helper (fetch-cargo-vendor-util.py) to download crate tarballs from
# crates.io. The helper does `session = requests.Session()` with no
# User-Agent override, so it sends the requests library default of
# "python-requests/X.Y.Z".
#
# As of 2026-06-03, crates.io returns HTTP 403 to that User-Agent
# (and to "curl/X.Y" and similar known scraper signatures) with the
# body:
#
#   {"errors":[{"detail":"We are unable to process your request
#     at this time. This usually means that you are in violation
#     of our API data access policy (https://crates.io/data-access).
#     ..."}]}
#
# A "Mozilla/5.0 ..." or "cargo X.Y.Z" UA passes the policy check
# (302 redirect to static.crates.io/crates/<name>/<name>-<ver>.crate
# which is the actual tarball URL).
#
# Verified live with `curl -s -i -A "<UA>" https://crates.io/api/v1/
# crates/aho-corasick/1.1.4/download`:
#   - default curl UA                  -> 403
#   - python-requests/2.32.5           -> 403
#   - Mozilla/5.0 (X11; Linux x86_64)  -> 302 OK
#   - cargo 1.94.0                     -> 302 OK
#   - empty string                     -> 302 OK
#
# === What this overlay does ===
#
# Re-callPackage `fetch-cargo-vendor.nix` from a patched copy of
# pkgs/build-support/rust/ in which `session = requests.Session()`
# is followed by `session.headers.update({"User-Agent": "..."})`.
# This makes every cargo-vendor fetch in the flake (xdp2-rs,
# proto-audit, every buildRustPackage consumer) send a compliant UA.
#
# === When to remove this ===
#
# Once upstream nixpkgs lands the User-Agent fix (track at
# https://github.com/NixOS/nixpkgs/blob/master/pkgs/build-support/
# rust/fetch-cargo-vendor-util.py), bump nixpkgs in flake.lock and
# drop this overlay.

final: prev:
let
  patchedRustBuildSupport = prev.applyPatches {
    name = "fetch-cargo-vendor-ua-fix";
    src = "${prev.path}/pkgs/build-support/rust";
    # Two replacements are needed (one before each consumer of
    # `requests.Session()`); the script also has a one-shot `with
    # session.get(url, ...)` call site. Inserting the header
    # immediately after the Session() constructor covers every later
    # `session.get(...)` call.
    #
    # `writers.writePython3Bin` lints the script with flake8 (only
    # E501 is in `flakeIgnore`), so we can't use the semicolon form
    # `Session(); session.headers.update(...)` — that triggers E702
    # (multiple statements on one line). The replacement uses a real
    # newline + four-space indent to stay flake8-clean.
    postPatch = ''
      sed -i \
        's|session = requests\.Session()|session = requests.Session()\n    session.headers.update({"User-Agent": "nixpkgs/fetch-cargo-vendor-util (https://github.com/NixOS/nixpkgs)"})|' \
        fetch-cargo-vendor-util.py

      # Sanity: confirm the substitution actually landed.
      grep -q '"User-Agent"' fetch-cargo-vendor-util.py \
        || (echo "fetch-cargo-vendor-ua-fix: substitution did not match" >&2; exit 1)
    '';
  };
in
{
  # rustPlatform is built via `makeScopeWithSplicing'` (see
  # pkgs/development/compilers/rust/make-rust-platform.nix). `buildRustPackage`
  # captures `fetchCargoVendor` from that scope at construction time, so a
  # plain `prev.rustPlatform // { fetchCargoVendor = X; }` would only replace
  # the top-level attr while every consumer (including
  # `rustPlatform.buildRustPackage`) keeps using the unpatched one.
  # `overrideScope` re-evaluates the whole scope so the new fetchCargoVendor
  # threads through everywhere.
  rustPlatform = prev.rustPlatform.overrideScope (fp: pp: {
    fetchCargoVendor = prev.callPackage
      "${patchedRustBuildSupport}/fetch-cargo-vendor.nix"
      { };
  });
}
