"""Build the Markdown report and its rotation checklist."""

from __future__ import annotations

from dataclasses import dataclass, field

from detectors import Finding, Rule, RULES_BY_ID, SEVERITY_ORDER
from rotation import plan_for


@dataclass
class Group:
    """One real secret, even if it appears in several places."""

    rule: Rule
    fingerprint: str
    masked: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return self.rule.severity

    @property
    def locations(self) -> list[str]:
        return [finding.location for finding in self.findings]

    @property
    def worst_path(self) -> str:
        return self.findings[0].path if self.findings else "unknown"


def group_findings(findings: list[Finding]) -> list[Group]:
    """Merge repeats of the same secret so one key gets one rotation plan."""
    groups: dict[tuple[str, str], Group] = {}
    for finding in findings:
        key = (finding.rule_id, finding.fingerprint)
        if key not in groups:
            groups[key] = Group(
                rule=RULES_BY_ID[finding.rule_id],
                fingerprint=finding.fingerprint,
                masked=finding.masked,
            )
        groups[key].findings.append(finding)
    ordered = sorted(
        groups.values(),
        key=lambda group: (
            SEVERITY_ORDER.get(group.severity, 9),
            group.rule.name,
            group.worst_path,
        ),
    )
    return ordered


def _short(text: str, limit: int = 90) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _locations(count: int) -> str:
    return "1 location" if count == 1 else f"{count} locations"


def render_markdown(
    groups: list[Group],
    meta: dict,
) -> str:
    total = sum(len(group.findings) for group in groups)
    critical = sum(1 for group in groups if group.severity == "Critical")
    high = sum(1 for group in groups if group.severity == "High")

    lines = [
        "# Secrets & Credential Leak Report",
        "",
        f"**Generated:** {meta['generated_at']}  ",
        f"**Scanned:** {', '.join(f'`{path}`' for path in meta['paths'])}  ",
        f"**Files read:** {meta['files_scanned']} "
        f"(skipped {meta['files_skipped']})  ",
        f"**Git history:** {'yes' if meta['git_used'] else 'no'}  ",
        f"**Unique secrets:** {len(groups)}  ",
        f"**Total locations:** {total}",
        "",
    ]

    if not groups:
        lines += [
            "## Result: no exposed secrets found",
            "",
            "The scanner checked every readable file against its rule set and found "
            "nothing that looks like a live credential.",
            "",
            "This is not proof of safety. Secrets can hide in images, PDFs, "
            "encrypted archives, browser profiles, and services this scan cannot "
            "reach. Rotate anything you already know was exposed.",
            "",
            "## What was checked",
            "",
            f"- {meta['files_scanned']} files across {len(meta['paths'])} path(s).",
            f"- {meta['rules_count']} detection rules.",
            f"- Git history: {'yes' if meta['git_used'] else 'no'}.",
            "",
        ]
        return "\n".join(lines)

    lines += [
        "## Start here",
        "",
        "Work top to bottom. Revoke first, replace second, clean up third. "
        "Deleting the file does **not** revoke the key.",
        "",
    ]
    for number, group in enumerate(groups, 1):
        lines.append(
            f"- [ ] **{number}. {group.rule.name}** ({group.severity}) - "
            f"`{group.masked}` - {_locations(len(group.findings))}"
        )
    lines.append("")

    lines += [
        "## Summary",
        "",
        "| # | Severity | Type | Secret | Locations |",
        "|---|---|---|---|---|",
    ]
    for number, group in enumerate(groups, 1):
        lines.append(
            f"| {number} | {group.severity} | {group.rule.name} | "
            f"`{group.masked}` | {len(group.findings)} |"
        )
    lines.append("")

    if critical or high:
        lines += [
            f"> **{critical} critical and {high} high-severity "
            f"{'secret' if high == 1 else 'secrets'}.** "
            "Revoke those before touching anything else. If you are unsure whether "
            "a key is live, rotate it.",
            "",
        ]

    lines += ["## Rotation plans", ""]

    for number, group in enumerate(groups, 1):
        rule = group.rule
        plan = plan_for(rule.provider)
        lines += [
            f"### {number}. {plan.title} - {rule.severity.upper()}",
            "",
            f"**Why it matters:** {rule.description}",
            "",
            f"**Secret:** `{group.masked}`  ",
            f"**Fingerprint:** `{group.fingerprint}` (same secret, same fingerprint)",
            "",
            "**Found in:**",
            "",
        ]
        for location in group.locations[:10]:
            lines.append(f"- `{location}`")
        if len(group.locations) > 10:
            lines.append(f"- ...and {len(group.locations) - 10} more location(s)")
        lines.append("")

        lines += [
            f"**Who can see it:** {plan.access}",
            "",
        ]
        if plan.revoke_url:
            lines += [f"**Revoke / rotate here:** {plan.revoke_url}", ""]

        lines += ["**Steps:**", ""]
        for step_number, step in enumerate(plan.steps, 1):
            lines.append(f"{step_number}. {step}")
        lines.append("")

        if rule.id == "dotenv_assignment":
            lines += [
                "**Exposed line (secret masked):**",
                "",
                "```text",
                group.findings[0].line_text,
                "```",
                "",
            ]

        lines += [
            f"**Verify the old one is dead:** {plan.verify}",
            "",
            "**Cleanup:**",
            "",
        ]
        lines += [f"- {item}" for item in plan.cleanup]
        lines += ["", "---", ""]

    lines += [
        "## Appendix - what this scan can and cannot see",
        "",
        f"- {meta['rules_count']} pattern rules checked {meta['files_scanned']} "
        f"readable files; {meta['files_skipped']} files were skipped as binary, "
        "too large, or in an ignored folder.",
        "- Secrets inside images, PDFs, browser profiles, and encrypted archives "
        "are not read.",
        "- A pattern match is a strong hint, not proof. A placeholder can look "
        "real; a real key can look like a placeholder.",
        "- Git history is only scanned when you pass `--git`, and only for "
        "repositories on this machine.",
        "- No file contents are uploaded anywhere. The report is generated locally.",
        "",
        "*Rotate first. Delete second. A deleted file does not cancel a key.*",
        "",
    ]
    return "\n".join(lines)
