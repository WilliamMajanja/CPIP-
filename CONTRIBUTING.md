# Contributing to CPIP

Thank you for your interest in CPIP — the Coffee Pot Internet Protocol.

## Code of Conduct

This project adheres to the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold its terms.

## What We Accept

- Bug fixes and edge-case patches
- New transport layer implementations
- Covert channel encoding improvements
- Documentation and spelling corrections
- Test cases and verification scripts
- Performance optimizations (especially for Raspberry Pi Zero)

## What We Do Not Accept

- Pull requests that add external Python dependencies beyond `cryptography`
- Changes that break RFC 2324 or RFC 7168 compliance
- Removal of the 418 "I'm a teapot" defense

## Getting Started

1. Fork the repository.
2. Make your changes on a feature branch.
3. Run the server and verify it starts without errors.
4. Test your change with the `htcpcp` CLI.
5. Submit a pull request.

## Code Style

- Python: follows the existing style in `server.py` (no formatter enforced,
  but be consistent with the surrounding code)
- C: `gcc -O2 -Wall -pthread` clean, zero warnings
- Bash: `set -euo pipefail`, `bash -n` clean
- No external dependencies beyond `cryptography`. Python standard library + `cryptography`
  for crypto. gcc + POSIX only for C code.

## Commit Messages

Write commit messages in the style:

```
component: brief description

Longer explanation if needed.
```

Examples:
- `radio: fix SPI register map for sx1276`
- `mesh: handle timeout during cross-transport forward`
- `docs: add mobile broadband env vars to readme`

## Testing

No formal test framework is used. Verify your changes by:

```bash
python3 server.py &
htcpcp status
htcpcp mesh status
htcpcp stats
```

Enable the relevant transport with env vars and check its endpoint.

## License

By contributing, you agree that your contributions will be licensed under
the Unlicense (public domain). See [LICENSE](LICENSE).
