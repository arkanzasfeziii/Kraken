# Changelog

## [2.0.0] - 2026-06-23

### Changed
- Complete rewrite from single-file to modular package architecture
- Each attack phase is an independent module under kraken/modules/
- K8s helpers extracted to kraken/utils/helpers.py

### Added
- kraken/modules/base.py — abstract base module
- kraken/utils/helpers.py — K8s connect, secret scanner, base64 decoder
- kraken/exceptions.py — typed exception hierarchy
- 16 unit tests (models, helpers, CLI)
- pyproject.toml, Makefile, CI pipeline, Dockerfile
- docs/ARCHITECTURE.md
- LICENSE, CONTRIBUTING, SECURITY, CHANGELOG

## [1.0.0] - 2026-06-20

### Added
- Initial release: K8s enumeration, secret dump, container escape,
  SA abuse, cloud bridge, etcd attack
