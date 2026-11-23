# Repository Guidelines

## Push & Release Workflow

Whenever a push and release is requested:

1. **Bump the version** in `src/wifit3/__init__.py` (`__version__`) to the target release version (e.g. `0.3.28`).
2. **Update `CHANGELOG.md`**: Create/add a `## <version> - <YYYY-MM-DD>` section at the top documenting all changes included in the release (grouped under `Added`, `Changed`, `Fixed`, etc.).
3. **Update `README.md`**: Update the current version references (header `> Version ...`, window title `wifit3-ng v...`, and `through **<version>**` line) and add a concise release summary entry under `## Fork additions (yadox666)` linking to the new `CHANGELOG.md` section.
4. **Verify, commit, tag, and push**: Stage all release changes (including `src/wifit3/__init__.py`, `CHANGELOG.md`, and `README.md`), commit, create the matching `v<version>` tag, and push the branch and tag to `origin`.
