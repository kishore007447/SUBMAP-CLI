# Contributing to SUBMAP

Thank you for your interest in contributing to SUBMAP!

## How to Contribute

### Bug Reports
- Use GitHub Issues
- Include reproduction steps, expected vs actual behavior
- Include your OS, Python version, and SUBMAP version

### Feature Requests
- Open an issue with [FEATURE] prefix
- Describe the use case and expected behavior

### Pull Requests
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Add/update tests
5. Run the test suite: `pytest tests/ -v`
6. Commit: `git commit -m "feat: add my feature"`
7. Push: `git push origin feature/my-feature`
8. Open a Pull Request

## Code Standards
- Python 3.12+
- Type hints on all functions
- Docstrings on public methods
- Follow existing code style (black, isort)
- 100-character line limit

## Security
- Never add hardcoded credentials
- Passive discovery by default
- Active features require explicit opt-in
- Follow responsible disclosure

## Legal
All contributions must be for defensive, authorized security testing purposes only.
