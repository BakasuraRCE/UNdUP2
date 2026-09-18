# UNdUP2

**dUP2 Project Unpacker and Decompiler**

---

## 1. Project Name and Description

**UNdUP2** is a command-line tool developed in Python that allows you to **unpack and decompile** executables generated with [dUP2](http://diup.sourceforge.net/) (dUP - Patcher Creator 2), a popular utility for creating binary patches.

### Problem It Solves

Executables created with dUP2 package an encrypted internal DLL containing patching modules (byte search and replace, among others). UNdUP2 automates the process of:

1. **Extracting** the encrypted DLL from the executable's RCDATA resources.
2. **Decrypting** the DLL using the rotative XOR algorithm with the key `0xDEADBEEF`.
3. **Reconstructing** the original `.dUP2` project file, allowing analysis or modification of patching modules.

### Technical Value

- Forensic analysis of existing binary patches.
- Reverse engineering of patchers to understand what modifications they perform.
- Recovery of dUP2 projects when the original source file has been lost.

**Author:** Bakasura  
**License:** [Unlicense](https://unlicense.org) (Public Domain)

---

## 2. System Architecture and Design

### Architectural Pattern

UNdUP2 implements a **monolithic CLI script architecture** with well-defined auxiliary functions. The design is intentionally minimalist and straightforward, optimized for a specific task without unnecessary abstractions.

### Main Data Flow

```
┌─────────────────┐
│  dUP2           │
│  Executable     │
│  (.exe)         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  lief.parse()   │  ← PE format parsing
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  RCDATA         │  ← Recursive navigation of RCDATA resources
│  Extraction     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  decrypt_bytes  │  ← Rotative XOR decryption (key: 0xDEADBEEF)
└────────┬────────┘
         │
         ├──────────────────────┐
         ▼                      ▼
┌─────────────────┐    ┌─────────────────┐
│  .dumped.dll    │    │  make_dup2_file │
│  (extracted DLL)│    │  (reconstruction)│
└─────────────────┘    └────────┬────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │  .dUP2 File     │
                       │  (project)      │
                       └─────────────────┘
```

### System Components

| Component | Responsibility |
|-----------|----------------|
| `main()` | CLI entry point, main flow orchestration |
| `resource_data_bytes()` | Recursive navigation of PE resource tree to extract data |
| `decrypt_bytes()` | Implementation of rotative XOR decryption algorithm |
| `make_dup2_file()` | Reconstruction of dUP2 project format |
| `align_16()` | Data alignment to 16 bytes (format requirement) |
| `padded_4_bytes_length()` | 4-byte padding calculation |
| `padded_16_bytes_length()` | 16-byte padding calculation |

### Design Justification

- **Simple monolith:** The limited scope of the problem (unpacking a specific format) doesn't justify additional abstraction layers.
- **Pure functions:** Auxiliary functions (`decrypt_bytes`, `align_16`) are deterministic and side-effect free, facilitating testing.
- **Single dependency:** LIEF handles all PE parsing complexity, allowing the code to focus on business logic.

### External Services

- **LIEF:** Library for parsing and manipulating executable formats (PE, ELF, Mach-O).

---

## 3. Code Style and Development Guidelines

### Design Philosophy

The project follows a **procedural programming approach with static typing**, prioritizing:

- Clarity over brevity.
- Small functions with single responsibility.
- Complete type hints for documentation and static validation.

### Formatting Rules

- **Indentation:** 4 spaces (Python standard).
- **Quotes:** Single (`'`) for strings, configured in Ruff.
- **Imports:** Sorted by isort (stdlib → third-party → local), with two blank lines after the import block.
- **Line limit:** Implicit in Ruff configuration (88 characters by default).

### Error Handling

The project uses **explicit exceptions** with descriptive messages:

```python
if binary is None:
    raise Exception(f'{exe_path.name} is not a valid PE file')

if not binary.has_resources:
    raise Exception(f'{exe_path.name} not have resources')
```

Validations are performed at critical points in the flow, failing early with contextual messages that include the processed file name.

### Recurring Patterns

1. **Guard clauses:** Validations at the beginning of functions that return early.
2. **Recursion for tree navigation:** `resource_data_bytes()` recursively navigates the PE resource structure.
3. **Bytearray for incremental construction:** The `.dUP2` file is built by progressively adding bytes.

### Logical Separation

The code is organized in implicit sections:

1. Utility functions (padding, alignment).
2. Decryption algorithm.
3. Resource extraction.
4. Entry point and main logic.
5. Project file generation.

---

## 4. Naming Conventions

### Variables and Constants

| Type | Convention | Examples |
|------|------------|----------|
| Local variables | `snake_case` | `dll_bytes`, `exe_path`, `dup2_content` |
| Constants | Implicit in code | `0xDEADBEEF` (encryption key) |
| Counters | Descriptive | `modules`, `modules_search_and_replace` |

### Functions

| Convention | Examples |
|------------|----------|
| Descriptive `snake_case` | `decrypt_bytes()`, `resource_data_bytes()` |
| `make_` prefix for constructors | `make_dup2_file()` |
| `padded_` prefix for padding calculations | `padded_4_bytes_length()` |
| `align_` prefix for alignment operations | `align_16()` |

### Classes and Types

No custom classes are defined. Type hints from libraries are used:

```python
res_manager: lief.PE.ResourcesManager
node: ResourceNode
```

### Files

| Pattern | Example |
|---------|---------|
| Main code | `main.py` |
| Tests | `tests/test_*.py` |
| Configuration | `pyproject.toml` |

### Output Files

| Type | Convention |
|------|------------|
| Extracted DLL | `{original_name}.dumped.dll` |
| Reconstructed project | `{original_name}.dUP2` |

---

## 5. Technology Stack and Dependencies

### Language and Runtime

| Component | Version | Notes |
|-----------|---------|-------|
| Python | `>= 3.14` | Requires modern language features |
| Package manager | `uv` | Modern dependency management tool |

### Production Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [LIEF](https://lief.re/) | `>= 1.0.0` | PE executable format parsing and manipulation |

### Development Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| pytest | `>= 9.1.1` | Testing framework |
| Ruff | (implicit) | Linter and formatter |

### Build System

```toml
[build-system]
requires = ["uv_build>=0.12.13,<0.13.0"]
build-backend = "uv_build"
```

---

## 6. Repository Structure

```
UNdUP2/
├── .git/                    # Git repository
├── .gitignore               # Git exclusions (Python template)
├── .python-version          # Python version for pyenv/uv (3.14)
├── .venv/                   # Virtual environment
├── LICENSE                  # Unlicense license (public domain)
├── README.md                # This file
├── main.py                  # Main source code
├── pyproject.toml           # Project configuration and dependencies
├── tests/                   # Tests directory
│   └── test_resource_data.py  # Unit tests
└── uv.lock                  # Dependency lock file (uv)
```

### Key Files

| File | Description |
|------|-------------|
| `main.py` | Main script with all unpacking logic |
| `pyproject.toml` | Project metadata, dependencies, and Ruff configuration |
| `uv.lock` | Exact dependency versions for reproducibility |
| `tests/test_resource_data.py` | Unit tests with LIEF structure mocks |

---

## 7. Environments and Configuration

### Supported Environments

The project is a local CLI tool that doesn't distinguish between environments. It runs directly on the user's machine.

### Configuration Variables

There are no environment variables or external configuration files. All parameters are passed via CLI.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `file_path` | `str` | Path to the dUP2 executable to process | Yes |

### Linting Configuration (Ruff)

```toml
[tool.ruff.lint]
select = [
    "E",   # pycodestyle (style)
    "W",   # pycodestyle (warnings)
    "F",   # Pyflakes (logic errors)
    "I",   # isort (import ordering)
    "B",   # flake8-bugbear (common errors)
    "C4",  # flake8-comprehensions
    "UP",  # pyupgrade (modern syntax)
    "N",   # pep8-naming
    "SIM", # flake8-simplify
    "ANN", # flake8-annotations (types)
]
```

---

## 8. CI/CD and Deployment Pipeline

### Current State

The project **does not have a configured CI/CD pipeline**. It's a local tool distributed as source code.

### Recommendations for Future Implementation

1. **GitHub Actions** for:
   - Test execution with `pytest`.
   - Linting validation with `ruff check`.
   - Type verification (optional, with `mypy`).

2. **PyPI Publishing** (if distribution is desired):
   - Build with `uv build`.
   - Upload with `uv publish` or `twine`.

---

## 9. Security

### Sensitive Data Handling

- The project **does not handle credentials or secrets**.
- It does not make network connections.
- It operates exclusively on local files.

### Security Considerations

| Aspect | Status |
|--------|--------|
| User input | Validates that the file is a valid PE |
| File writing | Writes to the same directory as the input file |
| Code execution | Does not execute code from the processed file |

### Potential Risks

- **Malicious files:** LIEF could be vulnerable to malformed PE files designed to exploit parser bugs. Keep LIEF updated.
- **File overwriting:** Output files (`.dumped.dll`, `.dUP2`) overwrite without confirmation if they already exist.

---

## 10. Prerequisites

### Operating System

- Linux, macOS, or Windows with Python 3.14+.

### Required Software

| Tool | Minimum Version | Installation |
|------|-----------------|--------------|
| Python | 3.14 | [python.org](https://www.python.org/downloads/) |
| uv | Latest | `pip install uv` or [docs.astral.sh/uv](https://docs.astral.sh/uv/getting-started/installation/) |

### Recommended Knowledge

- Basic familiarity with the command line.
- Understanding of PE (Portable Executable) format is helpful but not required.

---

## 11. Installation, Build, and Execution Guide

### Installation

#### 1. Clone the Repository

```bash
git clone <repository-url>
cd UNdUP2
```

#### 2. Install Dependencies with uv

```bash
# Create virtual environment and install dependencies
uv sync
```

Or alternatively with pip:

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install lief>=1.0.0
```

### Execution

#### Basic Usage

```bash
# With uv
uv run python main.py /path/to/patcher.exe

# With activated virtual environment
python main.py /path/to/patcher.exe
```

#### Complete Example

```bash
$ uv run python main.py ~/Downloads/MyPatcher.exe
UNdUP2: dUP2 Unpacker / Decompiler | Bakasura - 2024
Unpacked!
```

#### Output Files

After successful execution, two files are generated in the same directory as the input executable:

| File | Description |
|------|-------------|
| `MyPatcher.dumped.dll` | Decrypted DLL extracted from the executable |
| `MyPatcher.dUP2` | Reconstructed dUP2 project (importable in dUP2) |

### Running Tests

```bash
# With uv
uv run pytest

# With pytest directly
pytest tests/
```

### Code Verification (Linting)

```bash
# Check style
uv run ruff check .

# Format code
uv run ruff format .
```

---

## Additional Information

### Decryption Algorithm

dUP2 uses a rotative XOR encryption with the fixed key `0xDEADBEEF`. The algorithm:

1. Iterates over each byte of the encrypted content.
2. Applies XOR with the least significant byte of the key.
3. Rotates the key 1 bit to the right (ROR).
4. XORs the key with the original byte.
5. Adds the remaining counter to the key.

This encryption is **symmetric**: the same algorithm works for both encryption and decryption.

### .dUP2 File Format

```
┌────────────────────────────────────────┐
│ Header (16 bytes)                      │
│   [0-3]  Number of modules (uint32 LE) │
│   [4-7]  Comments offset               │
│   [8-15] Reserved (zeros)              │
├────────────────────────────────────────┤
│ Modules                                │
│   For each module:                     │
│     [4 bytes] Module length            │
│     [N bytes] Module data              │
├────────────────────────────────────────┤
│ Padding (16-byte alignment)            │
├────────────────────────────────────────┤
│ Comments                               │
│   For each type 4 module:              │
│     [4 bytes] Length (0x30)            │
│     [48 bytes] Empty comment           │
└────────────────────────────────────────┘
```

---

*Documentation automatically generated based on source code analysis.*
