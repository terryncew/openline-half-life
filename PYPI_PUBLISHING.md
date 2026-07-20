# PyPI publishing gate

The repository is prepared for PyPI Trusted Publishing, but the package is not published merely by merging this tree.

Before publishing the first release, create or claim the `openline-half-life` project on PyPI and configure a GitHub Trusted Publisher with:

- owner: `terryncew`
- repository: `openline-half-life`
- workflow: `publish.yml`
- environment: `pypi`

Then publish a GitHub release whose tag exactly matches the package version, for example `v0.3.0rc4`. The workflow builds and checks the wheel and sdist, publishes through OIDC, waits for the PyPI index, runs both one-command demo paths, and verifies the installed package outside a checkout.

The release workflow is intentionally separate from ordinary CI. A source-tree test cannot authorize publication and a successful publication cannot bypass the published-package smoke test.
