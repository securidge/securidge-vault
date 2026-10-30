# Releasing

Releases are built by [`.github/workflows/release.yml`](../.github/workflows/release.yml).
Nothing is published automatically: the workflow stages a **draft**
pre-release, and a maintainer reviews and publishes it.

## Cut a release

1. Make sure `main` is green (CI and Fuzz).
2. Set the version in the root `Cargo.toml` (`[workspace.package] version`), commit.
3. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.
   The tag must equal `v` + the Cargo version, or the workflow stops.
4. The workflow runs the tests on Windows and Linux, builds
   `SecuridgeVault.exe` and `securidge-vault.exe`, signs them (if set up,
   below), zips them with the licences, writes `SHA256SUMS.txt`, records
   [build provenance](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations)
   and creates a draft release.
5. Download the zip from the draft, check it on a clean Windows machine,
   then publish the draft (not as a pre-release, so that the
   `releases/latest/download/SecuridgeVault-windows-x64.zip` link in
   `download/README.md` and the main README points at it).

**From the website instead of git:** Releases → *Draft a new release* →
choose a new tag `v0.1.0` on `main` → *Publish release*. Publishing creates
the tag, which starts the workflow; it attaches the zip and checksums to that
release and fills in the notes (about 10 minutes, during which the download
link returns "not found").

**Dry run:** Actions → Release → *Run workflow* with the tag left empty
builds, signs-if-configured and packages the current commit and uploads it
as a workflow artifact. It creates no tag, release or attestation.

Users verify a download with:

```text
gh attestation verify SecuridgeVault-windows-x64.zip -R securidge/securidge-vault
```

## Code signing (not set up yet)

Without signing, the release notes say **Unsigned build** and Windows
SmartScreen warns on first run.

Since 1 June 2023, CAs must keep code-signing private keys on certified
hardware (HSM or token), so a certificate can no longer be exported as a
`.pfx` file and stored as a GitHub secret. The workflow therefore signs
through **SignPath**, whose
[SignPath Foundation](https://signpath.org/) programme issues a certificate
to open-source projects free of charge and keeps the key in its HSM.

To enable it:

1. Apply to SignPath Foundation for this repository and follow their
   onboarding (they check that binaries are built from this public repo).
2. In SignPath, create a project (default slug `securidge-vault`) with an
   artifact configuration for a zip containing the two `.exe` files, and a
   signing policy (default slug `release-signing`).
3. In GitHub → Settings → Secrets and variables → Actions:
   - secret `SIGNPATH_API_TOKEN`
   - variable `SIGNPATH_ORGANIZATION_ID`
   - optional variables `SIGNPATH_PROJECT_SLUG`, `SIGNPATH_POLICY_SLUG`
4. Cut a release. The *Check signatures* step fails the build if any
   binary is not validly signed.

The signing steps follow SignPath's published GitHub Actions example but
have not been exercised yet, because no SignPath account exists. Expect to
adjust the artifact configuration on the first signed release.

## Reproducibility

Release builds pass `--remap-path-prefix` (no build-machine paths in the
binary) and `/Brepro` (deterministic PE header). Bit-for-bit reproducible
builds are a v1.x goal (DESIGN.md §9) and have not been verified yet.
