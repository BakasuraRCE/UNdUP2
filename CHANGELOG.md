# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-17

### Added

- Project configuration with `pyproject.toml` using `uv` as package manager and build backend
- Dependency lock file `uv.lock` for reproducible builds
- Python version pinning with `.python-version` (Python 3.14)
- Ruff linter/formatter configuration with comprehensive rule set (pycodestyle, Pyflakes, isort, flake8-bugbear, etc.)
- Type hints throughout the codebase (`ResourceNode`, return types, parameter types)
- Validation for `None` return from `lief.parse()` in both `main()` and `make_dup2_file()`
- Validation for missing RCDATA resources
- New unit tests for error handling scenarios:
  - `test_make_dup2_file_raises_on_invalid_dll`
  - `test_make_dup2_file_raises_on_no_resources`
  - `test_make_dup2_file_raises_on_no_rcdata`
- Comprehensive README with full documentation (architecture, installation, usage, etc.)

### Changed

- Migrated from Pipenv (`Pipfile`, `Pipfile.lock`) to uv-based dependency management
- Upgraded minimum Python version from 3.11 to 3.14
- Upgraded LIEF dependency from 0.15.1 to >=1.0.0
- Refactored `resource_data_bytes()` to use direct attribute access instead of `getattr()` with defaults
- Refactored `make_dup2_file()` to use `bytearray` instead of string concatenation for better performance
- Improved code formatting: single quotes, consistent argument formatting
- Simplified loop in `make_dup2_file()` by removing redundant type annotation
- Extracted empty comment block creation to a variable for clarity
- Reformatted multi-line byte concatenation using parentheses instead of backslash continuation
- Updated tests to use single quotes and added type hints to test functions
- Simplified `FakeNode` class by deriving `is_data` from `data` parameter presence

### Removed

- Pipenv configuration files (`Pipfile`, `Pipfile.lock`)
- Redundant `getattr()` calls with default values in `resource_data_bytes()`
- Commented-out code (`# root = binary.resources`)
