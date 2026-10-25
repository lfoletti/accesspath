## What changes

<!-- One or two sentences: the behaviour before, the behaviour after. -->

## Failing first

<!-- For each rule or behaviour you add: the test that covers it, and the proof that it fails without the code
(the FAILED lines, or the mutation that a test catches). Give the command to run it again. -->

## Checks

- [ ] `ruff check .` and `ruff format --check .`
- [ ] `python -m pytest -m "not network"`
- [ ] No credentials, private addresses or personal data in code, tests or fixtures
