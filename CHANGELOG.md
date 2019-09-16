# Changelog
All notable changes to this project will be documented in this file.

## 2019-09-16
### Added
- Provide documentation for requireUsername and language fields
  (https://gitlab.com/blocksq/authcore-js/issues/16)

### Changed
- Replace SRP6a password authentication protocol with SPAKE2+ for better
  performance. Please reset all account passwords before login
  (https://gitlab.com/blocksq/authcore/issues/394)