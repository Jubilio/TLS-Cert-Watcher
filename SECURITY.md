# Security policy

## Supported versions

Security fixes are provided for the latest release.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Security > Report a vulnerability** workflow. If that option is unavailable, contact `jubiliomausse5@gmail.com`. Do not open a public issue before a fix is available.

Include the affected endpoint or component, reproduction steps, impact, and any suggested mitigation. Please avoid accessing systems or data that you do not own or have permission to test.

## Deployment guidance

- The scanner accepts public targets by default. Set `ALLOW_PRIVATE_TARGETS=true` only on a trusted, access-controlled network.
- Do not expose a private-target-enabled deployment directly to the internet.
- Configure `CORS_ORIGINS` explicitly when browser clients run on another origin.
- Put shared or public deployments behind authentication and a reverse proxy with TLS.
- Keep the container image and npm dependencies updated.
