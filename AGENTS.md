# Server runtime contribution rules

- Preserve CommonJS and Node.js 18+ compatibility.
- Keep this runtime application-neutral and independently installable.
- Do not add MFS, Hub, Team business behavior or application policy.
- Keep intrinsic runtime schemas and migrations package-owned under `schemas/`.
- Treat `schemas/SCHEMA_MANIFEST.json` as the executable schema inventory.
- Runtime may require `DEFAULT_ORG_ID = 1` and
  `NOBODY_UID = ffffffffffffffff`, but must not provision organisation,
  nobody, guest or system identities.
- Do not add hidden imports from transient, sibling repositories, `target/**`,
  `sources/**`, parent `node_modules` or `NODE_PATH`.
- `npm ci`, `npm test` and `npm pack` must work from a standalone clone.
- Do not publish npm packages without explicit R1 authorization.
- Do not begin Phase 4.6 or later work without explicit authorization.
