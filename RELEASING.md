# Releasing PortReveal

PortReveal uses [semantic versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.
GitHub Releases are created from annotated tags named `vX.Y.Z`.

## Version manifests

Keep these in sync (the bump script updates all of them):

- `package.json`
- `frontend/package.json`
- `package-lock.json` (root and workspace package entries)
- `backend/pyproject.toml`
- `backend/app/__init__.py` (`__version__`)

Check without changing anything:

```bash
npm run version:check
# or require a specific version:
node scripts/version.mjs check 1.0.0
```

## Cut a release

1. On an up-to-date `main`, bump the version:

   ```bash
   npm run version:bump -- patch   # or minor / major / 1.2.3
   ```

2. Update `CHANGELOG.md`: add a `## [X.Y.Z] - YYYY-MM-DD` section at the top
   (below the intro) with Added / Changed / Fixed notes as needed.

3. Commit on `main` (via PR if that is your usual flow):

   ```bash
   git add package.json frontend/package.json package-lock.json \
     backend/pyproject.toml backend/app/__init__.py CHANGELOG.md
   git commit -m "Release X.Y.Z"
   git push origin main
   ```

4. Wait until CI is green on that commit (backend, frontend, e2e, alembic-check,
   alembic-postgres).

5. Create and push an annotated tag for the same commit:

   ```bash
   git tag -a vX.Y.Z -m "PortReveal X.Y.Z"
   git push origin vX.Y.Z
   ```

6. The **Release** workflow runs on `v*.*.*` tags. It:
   - fails if the tag does not match the manifests
   - requires the CI checks above to have succeeded on the tagged commit
   - builds the frontend and attaches `portreveal-vX.Y.Z-frontend-dist.tar.gz`
   - publishes a GitHub Release titled `PortReveal X.Y.Z` using the matching
     CHANGELOG section (plus GitHub auto-generated notes)

Do not force-push tags. Do not push to `main` from release automation; only push
the version tag after `main` already has the bump commit and green CI.
