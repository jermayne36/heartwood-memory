# Hermes integration maintainer note

## Changes

- The source adapter handles Hermes session switches and accepts the optional
  `turn_author` argument without changing the principal mapping.
- The integration contract targets Hermes v0.22.4 at
  `4d04303818b61bf3aa09278af48356315515965b` and exercises its real provider,
  plugin loader and memory manager. Explicit opt-in fails if Hermes is missing
  or the installed checkout does not match the pin.
- `plugins/hermes/` adds a directory plugin using `heartwood-memory==0.2.10`,
  a session-switch compatibility shim, setup instructions, a release check,
  and draft Community catalog material. Nothing has been submitted upstream.

## How to test

Use a fresh source checkout and an isolated Python 3.14 environment with a copied
interpreter, as described in `plugins/hermes/README.md`. Then run:

```sh
python -m ruff check .
python -m build --wheel --sdist
bash plugins/hermes/check_release.sh python
HEARTWOOD_TEST_HERMES=1 HF_HUB_OFFLINE=1 python -m pytest -q
```

The contract suite checks the imported Hermes checkout rather than its placeholder
package version. The full suite uses synthetic stores. Cached models are needed
for any separate offline memory-session demonstration.

## Known limits and follow-up

- The default suite skips the optional Hermes contract. The release workflow
  still needs to invoke `plugins/hermes/check_release.sh` and require its success
  before publishing. Automatic release enforcement is pending.
- The catalog YAML is a draft. Replace `REPLACE_WITH_REVIEWED_MERGED_COMMIT_SHA`
  with the reviewed merge commit, then validate the YAML and plugin admission
  against that exact source before submitting. No prior implementation pin
  should be reused. The draft is intentionally not ready for catalog admission.
- Memory lifecycle checks do not establish live model chat, catalog installation,
  or desktop onboarding behaviour. Community placement is proposed only.
- Recall may search other sessions in the configured tenant. Sessions are not
  isolation boundaries. The forget tool erases the whole named subject.
- Shared adapter and platform guides still describe the earlier setup. Use the
  plugin README for the current contract and installation instructions.
- The existing rotation demonstration resolves the Python executable before
  launching a subprocess; a copied interpreter keeps its dependencies available.
