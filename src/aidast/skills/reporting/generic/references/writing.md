# Reader-facing writing

Write the general report in the requested language, retaining exact endpoint names and technical
terms where helpful. The reader needs the affected feature, demonstrated behavior,
impact, and practical next step. Copy all source bindings and keep structured
evidence citations exactly as required by the schema.

Use a specific title naming the affected feature and demonstrated weakness or
behavior. Avoid vague titles such as “controlled changes” or “bounded result”.
Do not promote a suspected mechanism, unverified identity, or unobserved impact
to a fact merely to make the title stronger.

Lead the summary with what happened and what it allows. Explain the normal
request, comparison request, and repeated target results in plain language.
State limitations once in the impact section, separating confirmed effects from
what was not verified. Do not repeatedly discuss internal audit machinery,
semantic axes, assertion IDs, or context hashes in the prose.

Each reproduction step is one action or recorded observation. Do not prepend
step numbers; the renderer numbers the structured list. Include exact requests
only when the supplied evidence contains them. If it does not, state that the
sequence summarizes recorded validation and cannot be replayed as written.
Explain the observed signal, rather than naming an internal assertion.

Give concrete remediation tied to the demonstrated behavior, phrased as a
recommendation. Do not invent payloads, credentials, response content, affected
users, or a tested fix. Evidence IDs belong in structured citations, not text.
