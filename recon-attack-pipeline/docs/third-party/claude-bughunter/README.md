# Claude-BugHunter source attribution

The supplied local `attack` bundle identifies Claude-BugHunter at commit
`e49b9da698bfe830302f0ae49ea02e41cc5cf876` as its upstream.
`LICENSE`, `CREDITS.md`, and `SOURCE.json` are preserved verbatim from
that bundle's `vendor/` directory. They describe the source bundle and its
upstream, including material beyond the scope of this project.
In particular, the historical adaptation statement in `SOURCE.json`
does not describe this project's implementation.

`inventory.json` records SHA-256 hashes measured from all 60 supplied
`SKILL.md` files: 59 under `library/` and one under `controller/`.
Upstream byte identity and authorship of the local controller have not been
independently verified. The inventory records local provenance, not a claim
that all 60 files are unmodified upstream files.

AI-Dast packages the supplied controller and 59 library `SKILL.md` documents
under `src/aidast/skills/attack/`. Runtime loading verifies each document
against the SHA-256 inventory before it is supplied to the Attack planner.
The original license and community attribution are retained for provenance.

Catalog entries remain non-executable metadata. A signal match allows the
matching document to be loaded as model guidance; it is not itself a finding,
permission to test, or an executable playbook. Tests are exposed separately as
pre-authorized IDs by the trusted Attack executor. An empty mapping means that
the current evidence taxonomy does not justify automatic routing.

The upstream repository identified by the supplied bundle is
<https://github.com/elementalsouls/Claude-BugHunter>.
