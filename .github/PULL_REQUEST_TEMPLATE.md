# Pull Request

## Description

Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Transport layer implementation
- [ ] Covert channel improvement
- [ ] Cryptographic improvement

## Checklist
- [ ] No external Python dependencies added (stdlib only)
- [ ] Server starts without errors
- [ ] Tested with `python3 test_cpip.py`
- [ ] Tested with `htcpcp status` and `htcpcp mesh status`
- [ ] Crypto changes: KEM round-trip still passes (200+ iterations)

## Crypto Changes?

If this PR modifies `kyber.py` or any cryptographic code, verify:
- [ ] `python3 -c "from kyber import Kyber768; ok=0; [exec('pk,sk=Kyber768.keygen()\nc,ss=Kyber768.encaps(pk)\nss2=Kyber768.decaps(sk,c)\nok+=(ss==ss2)') for _ in range(200)]; print(f'KEM: {ok}/200')"`