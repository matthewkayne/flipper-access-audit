# Flipper App Catalog Submission

Notes on getting Access Audit listed in the [Flipper Application Catalog](https://github.com/flipperdevices/flipper-application-catalog).

## Requirements checklist

- [x] `application.fam` with `fap_version`, `fap_author`, `fap_description`, `fap_weburl`
- [x] CI builds pass on official release SDK
- [x] Stable tagged release with FAP attached
- [ ] 10×10 app icon (`images/icon.png`, 1-bit PNG)
- [ ] At least one screenshot in `docs/screenshots/`
- [ ] First-submission PR to the catalog repo

## First submission (manual)

1. Fork https://github.com/flipperdevices/flipper-application-catalog
2. Create `applications/Tools/access_audit/manifest.yml`:

```yaml
sourcecode:
  type: git
  location:
    origin: https://github.com/matthewkayne/flipper-access-audit
    commit_sha: <sha of the tagged release commit>
```

3. Open a PR against the catalog `main` branch.
4. Wait for review.

## Automated updates (after first approval)

Once the first PR is merged, subsequent releases can be pushed automatically.

The `release.yml` CI workflow creates a GitHub Release on every `v*` tag. To also auto-update the catalog, add a second job to `release.yml` (requires a `CATALOG_PAT` secret with `repo` scope on the catalog fork):

```yaml
  catalog-update:
    name: Update catalog manifest
    needs: build-and-release
    runs-on: ubuntu-latest
    steps:
      - name: Update catalog manifest
        uses: flipperdevices/flipper-application-catalog-update-action@v1
        with:
          token: ${{ secrets.CATALOG_PAT }}
          appid: access_audit
```

> The catalog update action is a placeholder — check the catalog repo for the current recommended automation approach.
