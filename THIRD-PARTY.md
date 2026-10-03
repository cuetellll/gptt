# Third-party engines

MahyarVPN runs separate upstream executables; it does not copy Aether-GUI's
React or Rust source. Its model-2 profile uses the documented Aether CLI.

- Aether: https://github.com/CluvexStudio/Aether, pinned to v1.6.0,
  GNU AGPL version 3. The Windows build verifies the release archive with
  SHA256SUMS.txt. The installer bundles its upstream license and source notice;
  the portable archive and release artifacts also include the upstream source
  snapshot. Preserve these files and upstream attribution.
- Aether-GUI: https://github.com/MatinSenPai/Aether-GUI, architecture reference
  only. No source from this project is included.
- sing-box: https://github.com/SagerNet/sing-box, the existing routing engine.
  Preserve its GPL license and comply with its corresponding-source obligations
  when distributing binaries.

Before public distribution, audit BOTH engines' licenses, corresponding source,
build scripts and any submodule/dependency source required to reproduce the
exact upstream binaries. A GitHub tag archive alone is not a guarantee of
complete Corresponding Source. If you modify an engine, supply its modified
source as required. This source-code update is not a license clearance.

Model 2 uses anonymous consumer WARP registration, not Zero Trust enrollment.
Availability, legal use, network compatibility and Cloudflare policies remain
the distributor's and user's responsibility. No connection success is guaranteed.
