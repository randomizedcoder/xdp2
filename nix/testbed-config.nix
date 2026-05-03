# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# testbed-config — pure-Nix TOML loader and validator for the
# flow-dissector matrix benchmark on physical hardware.
#
# Schema documented in:
#   docs/flow-dissector-matrix-physical-testbed.md §3
#
# Consumer (in flake.nix):
#   let testbedLib = import ./nix/testbed-config.nix { inherit lib; };
#   in testbedLib.loadAll ./testbeds
#
# Output shape (per config):
#   {
#     testbed = { name = "..."; description = "..."; };
#     hosts   = { dut = { hostname = "..."; ... }; generator = {...}; };
#     hostsList = [ <original list, preserved for ordering> ];
#     nic     = { driver = "i40e"; ... };
#     run     = { iterations_combo = 200; ... };
#   }

{ lib }:

let
  # Supported sets — validation rejects values outside these. Add new
  # entries here when a new uarch / driver is supported by the rest
  # of the implementation (e.g. Phase 9 lands mlx5_core). The
  # design's §4 is the source of truth.
  validUarchs = [
    "zen1" "zen2" "zen3" "zen4"
    "skylake" "icelake" "icx" "sapphirerapids"
    "neoverse-n1" "neoverse-v1"
  ];
  validDrivers = [ "i40e" "ice" "mlx5_core" "bnxt_en" ];
  validFlowDirector = [ "ethtool" "tc-flower" "devlink" ];

  # Throw a clear error if `cond` is false.
  must = cond: msg: if cond then null else throw "testbed-config: ${msg}";

  validateHost = h:
    let
      _name = must (h ? hostname) "host missing 'hostname' field";
      _role = must (h ? role) "host '${h.hostname or "<unknown>"}' missing 'role'";
      _uarch = must (lib.elem h.cpu_uarch validUarchs)
        "host '${h.hostname}': cpu_uarch '${h.cpu_uarch}' not in supported set ${toString validUarchs}";
      _isolated = must (h ? isolated_cpus)
        "host '${h.hostname}': missing 'isolated_cpus'";
    in
    builtins.seq _name (
      builtins.seq _role (
        builtins.seq _uarch (
          builtins.seq _isolated h
        )
      )
    );

  validateNic = nic:
    let
      _driver = must (lib.elem nic.driver validDrivers)
        "nic.driver '${nic.driver}' not in supported set ${toString validDrivers}";
      _fd = must (lib.elem nic.flow_director validFlowDirector)
        "nic.flow_director '${nic.flow_director}' not in supported set ${toString validFlowDirector}";
    in
    builtins.seq _driver (builtins.seq _fd nic);

  validate = raw:
    let
      hosts = raw.hosts or (throw "testbed-config: missing [[hosts]] entries");
      validatedHosts = map validateHost hosts;
      duts = builtins.filter (h: h.role == "dut") validatedHosts;
      gens = builtins.filter (h: h.role == "generator") validatedHosts;

      _dutCount = must (builtins.length duts == 1)
        "exactly one host must have role='dut', got ${toString (builtins.length duts)}";
      _genCount = must (builtins.length gens <= 1)
        "at most one host may have role='generator', got ${toString (builtins.length gens)}";

      hostsByRole = lib.listToAttrs (
        map (h: { name = h.role; value = h; }) validatedHosts
      );

      validatedNic = validateNic raw.nic;
    in
    builtins.seq _dutCount (
      builtins.seq _genCount {
        testbed = raw.testbed;
        hosts = hostsByRole;
        hostsList = validatedHosts;
        nic = validatedNic;
        run = raw.run or {};
      }
    );

in
{
  # loadTestbedConfig: parse + validate a single TOML file.
  loadTestbedConfig = configFile:
    validate (builtins.fromTOML (builtins.readFile configFile));

  # loadAll: discover every *.toml under configsDir and return an
  # attrset keyed by basename (without the .toml suffix). A directory
  # without any *.toml yields an empty attrset.
  loadAll = configsDir:
    let
      entries = builtins.readDir configsDir;
      tomlFiles = lib.filterAttrs
        (n: t: t == "regular" && lib.hasSuffix ".toml" n)
        entries;
    in
    lib.mapAttrs'
      (filename: _: {
        name = lib.removeSuffix ".toml" filename;
        value = validate (
          builtins.fromTOML (builtins.readFile (configsDir + "/${filename}"))
        );
      })
      tomlFiles;

  # Re-export for downstream consumers (Phase 2 adapter).
  inherit validUarchs validDrivers validFlowDirector;
}
