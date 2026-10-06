# Analysis contract

Read run.json for actual finding/evidence IDs. Create analysis.json with init-analysis, then edit it. The JSON schema is a portable contract; the dependency-free validator enforces it plus cross-file evidence references, source hashes, and control rules. Schema validity alone does not prove claims true.

## Top level
- schema_version: 1.
- selection_notes: explain why these findings were selected, including fewer than three.
- limitations: nonempty list of whole-analysis limitations.
- context_notes (optional): evidence-cited context that is not an advisory finding. Each item has text and nonempty evidence_ids, and no other keys. Use it for unversioned or undeclared dependencies and configuration observations. It never substitutes for a finding.
- assessments: zero or more assessed findings. Each has finding_id, status, rationale, evidence_ids, and nonempty limitations. Status: unknown / potentially_applicable / ruled_out_under_evidence. Unassessed findings remain visible.
- scenarios: zero to three, each for a distinct real finding.

## Scenario
Required keys: id, finding_id, title, evidence_ids, facts, assumptions, unknowns, application_evidence_gap, prerequisites, steps, hypothetical_impact, limitations.

Include every finding evidence_id (package + complete advisory records) in scenario evidence_ids. Facts contain text and nonempty evidence_ids. Every referenced ID must exist in run.json; fact/control/step references must be a subset of the scenario references. Cite actual relevant source excerpts when available. Describe missing application evidence explicitly in application_evidence_gap. Describe unverified source/SBOM alignment even if source calls are found.

Prerequisites: 1–8 objects with id, label, required_value (Boolean), initial (string true/false/unknown), basis (observed/assumption), explanation, evidence_ids. IDs must be unique per scenario. Observed controls need evidence; true/false initial values require observed basis. Assumptions always start unknown. Use required_value false for a documented mitigation that blocks the modeled path when enabled. Do not imply enabling one mitigation protects all paths.

Steps: 2–8 conceptual descriptions, each with text and evidence_ids (possibly empty for explicitly hypothetical mechanics). Do not embed runnable payloads, commands, HTML, or JavaScript. The renderer treats all these fields as plain text.

Simulation semantics: a known control contradicting its required value yields blocked; otherwise any unknown yields unknown; otherwise satisfied. A blocker can be decisive for this modeled path even when another prerequisite is unknown. None of these outcomes is exploit validation. A control changed by the user is always a what-if assumption, including changed observed controls.

See example-analysis.json for one clearly synthetic example. Use real IDs and evidence when analyzing a repository. Never reuse demonstration advisories as live findings.
