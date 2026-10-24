# Contributing to ICS Security Stress Testing Platform

Thank you for your interest in contributing! This document provides guidelines and information for contributors.

## Code of Conduct

Please be respectful and constructive in all interactions. We are committed to providing a welcoming and inclusive experience for everyone.

## How to Contribute

### Reporting Bugs

1. Check the [issue tracker](https://github.com/YOUR_USERNAME/ics-stress-testing-platform/issues) to see if the bug has already been reported.
2. If not, open a new issue with:
   - A clear, descriptive title
   - Steps to reproduce the problem
   - Expected behavior vs. actual behavior
   - Your environment (OS, Python version, Docker version if applicable)
   - Relevant log output or screenshots

### Suggesting Enhancements

Open an issue with the "enhancement" label. Describe:
- The use case or problem you're trying to solve
- Your proposed solution
- Any alternatives you've considered

### Submitting Pull Requests

1. Fork the repository and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. Ensure your code follows the existing style conventions.
4. Update documentation if needed (README, docstrings, comments).
5. Submit your pull request with a clear description of the changes.

## Development Setup

### Prerequisites

- Kali Linux (or compatible Debian-based distro)
- Python 3.10+
- Root privileges (for raw socket operations)

### Local Development

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ics-stress-testing-platform.git
cd ics-stress-testing-platform

# Install dependencies
sudo ./install.sh

# Start the platform
sudo ./run.sh
```

### Docker Development

```bash
docker compose up -d --build
docker compose logs -f
```

## Adding New Test Items

1. Create a new plugin file in `app/plugins/` following the contract in `app/plugins/common.py`.
2. Your plugin must define:
   - `NAME` — display name for the test item
   - `CATEGORY` — protocol category (e.g., "Modbus TCP", "OPC UA")
   - `PROTOCOL` — protocol identifier
   - `TEST_TYPE` — type of test (e.g., "flood", "malformed", "auth_bypass")
   - `get_param_schema()` — returns a dict describing configurable parameters
   - `run(target, port, duration, rate, extra, stop_event, progress_cb)` — the test logic
3. Register the test item in `app/registry.py` by adding an entry to `TEST_ITEMS`.
4. Run the healthcheck to verify dependencies: `python scripts/run_healthcheck.py`

## Adding New Monitors

1. Create a new monitor file in `app/monitors/`.
2. Define `TYPE`, `NAME`, and `sample(config) -> dict`.
3. Register in `app/monitors/__init__.py` by adding to `REGISTRY`.

## Style Guidelines

- Python: Follow PEP 8. Use type hints where practical.
- Docstrings: Use triple-quoted strings for module and function documentation.
- Comments: Write in English for code comments; UI strings may be in Traditional Chinese.
- Commit messages: Use clear, descriptive messages in English.

## Security Considerations

- **Never** add test items that perform source IP/MAC spoofing or reflection/amplification attacks.
- All test items must target only the operator-specified single target.
- Every test item must respect the configurable duration cap and stop event.
- If your contribution introduces new network capabilities, document them clearly.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
