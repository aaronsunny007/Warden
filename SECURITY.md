# Security policy

Warden is a security research project. It is a lab-only system: all data is synthetic and the
red-team components attack **only Warden's own lab**.

## Reporting a vulnerability

If you find a vulnerability **in Warden itself** (the gateway, policy IR, detection cascade, or
control plane), please report it privately:

- Open a [GitHub security advisory](https://github.com/aaronsunny007/Warden/security/advisories/new)
  (preferred), or
- email the maintainer listed in the repository profile.

Please include a description, affected component and version/commit, and a minimal reproduction.
Do not open a public issue for an unfixed vulnerability. We aim to acknowledge within a few days.

## Scope

In scope:

- Bypass of a Warden control that should have held (e.g. a signed-bundle verification flaw, a
  taint-tracking escape, an argument/output check that can be trivially evaded).
- A way to make the validation gate promote a harmful enforce rule without G8 approval.
- Anything that lets the policy TCB (trusted compiler, bundle loader) execute attacker input or
  load an unsigned/tampered bundle.

Out of scope:

- Findings that require compromising the host, the signing key, or a trusted operator's G8 approval.
- The behaviour of the deliberately malicious lab servers and the attack corpus — these are
  intentional test fixtures.
- Model-provider safety, model weights, or prompt jailbreaks that never reach a tool call.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full trust model.

## Handling of secrets

No secrets are committed to this repository. Signing keys are generated at runtime into volumes;
admin tokens come from the environment. CI runs gitleaks, Semgrep and Trivy on every push.

## Responsible use

Use the learning loop and red-team tooling against the bundled lab only. Do not point them at
systems you do not own or are not explicitly authorised to test.
