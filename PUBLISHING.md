# Publishing depfence to PyPI

The package name **`depfence` is currently unclaimed** on PyPI. Claiming it is the
priority — until then anyone could register the name and ship a look-alike.

Current state (verified locally):

- `python -m build` produces `dist/depfence-0.5.0.tar.gz` + `depfence-0.5.0-py3-none-any.whl`.
- `twine check dist/*` → **PASSED** (both artifacts).
- A clean install of the wheel exposes working `depfence`, `depfence scan`, and
  `depfence-mcp` entry points; metadata carries all four `project.urls`.
- `.github/workflows/publish.yml` is wired for **PyPI Trusted Publishing** (OIDC,
  no long-lived token) using environment `pypi`, triggered on GitHub Release.

There are no PyPI/TestPyPI credentials on this machine, so the final upload must be
done by you. Two paths below.

---

## Path A — Claim the name now with an API token (fastest)

Use this to grab `depfence` and ship 0.5.0 in one shot.

1. Create/sign in to a PyPI account at <https://pypi.org/account/register/> and enable 2FA.
2. Create an API token: **Account settings → API tokens → Add token**. For the very
   first upload the project does not exist yet, so scope it to **"Entire account"**
   (you can delete it and create a project-scoped token afterwards).
3. (Optional but recommended) dry-run on TestPyPI first:
   ```bash
   python -m twine upload --repository testpypi dist/*
   # username: __token__   password: <your TestPyPI token>
   # then verify:  pip install -i https://test.pypi.org/simple/ depfence
   ```
4. Upload to real PyPI:
   ```bash
   cd ~/dev/depfence
   python -m build                 # rebuild if dist/ is stale
   python -m twine check dist/*
   python -m twine upload dist/*
   # username: __token__   password: <your PyPI token, starts with pypi->
   ```
5. Confirm: <https://pypi.org/project/depfence/> and `pip install depfence`.

After the first upload, replace the account-scoped token with a **project-scoped**
one, or switch entirely to Path B for future releases.

---

## Path B — Trusted Publishing for ongoing releases (recommended)

`publish.yml` already implements this; it just needs PyPI configured to trust it.

1. Add a publisher on PyPI:
   - If the project does **not** exist yet: <https://pypi.org/manage/account/publishing/>
     → **Add a pending publisher** with:
     - PyPI Project Name: `depfence`
     - Owner: `ericrihm`
     - Repository name: `depfence`
     - Workflow name: `publish.yml`
     - Environment name: `pypi`
   - If the project already exists (e.g. after Path A): project → **Settings →
     Publishing → Add a trusted publisher** with the same values.
2. In GitHub: **Settings → Environments → New environment** named `pypi`
   (add reviewers/branch protection if you want a manual gate before release).
3. Cut a release: tag and publish a GitHub Release (e.g. `v0.5.0`). The `publish`
   job builds, then `pypa/gh-action-pypi-publish` uploads via OIDC — no token.

---

## Notes

- A given version can only be uploaded to PyPI once; bump `version` in
  `pyproject.toml` for any re-release.
- `gh-action-pypi-publish` in `publish.yml` is SHA-pinned to a verified commit
  (`cef2210…` = v1.14.0). Re-pin only with `ratchet`, never by hand
  (see `docs/maintaining-action-pins.md`).
