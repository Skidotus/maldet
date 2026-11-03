# YARA Forge rules

`yara-rules-core.yar` is the **core** package of
[YARA Forge](https://github.com/YARAHQ/yara-forge) (release and rule count in
`VERSION`), run by `scanner.py:run_yara_forge()` alongside MalDet's own
`rules.yar`. Refresh it with `python3 update_yara_forge.py`.

## Why both rule sets

- `rules.yar` holds **behaviour** rules: decode-then-execute,
  download-then-execute, persistence. They can catch code nobody has seen
  before, which is the point for supply-chain attacks.
- Forge holds **fingerprints** of known malware families and hacking tools
  (Cobalt Strike, njRAT, NotPetya, ...). Very precise, but only for what
  someone has already written a rule for.

## Measured before adoption (2026-11-03, release 20261101)

Run over the 174 repositories in the development database that could still
be cloned (4 deleted, 3 too large to clone within 5 minutes):

| | rules.yar (old) | Forge core |
|---|---|---|
| repos with a hit | 131 (75%) | 15 (9%) |
| most common rule fires in | 55% of repos | 3.4% of repos |
| hits in vendored code | — | 0 |
| median / max scan time per repo | 0.4s / 77s | 0.5s / 13s |
| peak memory (largest repo) | 728MB | 770MB |

All 15 Forge repos are malware sample collections or offensive tools
(InQuest/malware-samples, The-MALWARE-Repo, Empire, pupy, nishang, ...),
plus two security-adjacent ones that contain attack code by design
(stamparm/maltrail, PayloadsAllTheThings). No hit in ordinary software. 97
of the flagged files were missed by both ClamAV and `rules.yar`.

## Severity

Forge rules carry a 0-100 `score`, not a severity. `scanner.forge_severity()`
maps score 75+ to high and 65-74 to medium (core holds nothing below 65).
Rules whose name contains `HKTL_` (signature-base's hacking-tool prefix) are
always medium and labelled `[hacking tool]` in the finding text: a red-team
framework is dual-use, not malware.

## Licensing

Rules are collected from many sources and **each rule carries its own
`author`, `reference` and `license` meta**, which must be kept. In release
20261101 the most common licences are CC BY-SA 4.0 (1,622 rules) and the
Detection Rule License 1.1 (signature-base, 379 rules); both permit use with
attribution. YARA Forge itself excludes Elastic's rules (Elastic License
2.0 restricts hosted use), which matters because MalDet is a public
service. Do not hand-edit the file: changes are lost on the next update and
blur the attribution.
