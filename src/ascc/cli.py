import json
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ascc.correlate.run import correlate as run_correlate
from ascc.correlate.run import effective_confidence
from ascc.ingest.registry import parser_for
from ascc.schema.models import ScanRun

app = typer.Typer(name="ascc", help="AI Security Command Center")


def _make_console() -> Console:
    width = int(os.environ["ASCC_CONSOLE_WIDTH"]) if "ASCC_CONSOLE_WIDTH" in os.environ else None
    return Console(width=width)


@app.callback()
def main() -> None:
    """AI Security Command Center — correlation layer over Trivy, Prowler, Checkov."""


@app.command()
def correlate(
    input: Path = typer.Option(
        ...,
        "--input",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help="Path to a directory of scanner fixtures (Trivy/Prowler/Checkov JSON).",
    ),
) -> None:
    console = _make_console()
    scan_runs: list[ScanRun] = []
    skipped: list[tuple[str, str]] = []

    for file in sorted(input.iterdir()):
        if not file.is_file():
            continue
        try:
            data = json.loads(file.read_text())
        except json.JSONDecodeError:
            skipped.append((file.name, "not valid JSON"))
            continue
        parser_cls = parser_for(data)
        if parser_cls is None:
            skipped.append((file.name, "unrecognized format"))
            continue
        scan_runs.append(parser_cls().parse(file))

    if not scan_runs:
        console.print(f"[red]No recognized scanner files in[/red] {input}")
        raise typer.Exit(code=1)

    scanners = ", ".join(sorted({run.scanner for run in scan_runs}))
    console.print(
        f"[bold]Read {len(scan_runs)} file(s)[/bold] ({scanners}), skipped {len(skipped)}"
    )
    for name, reason in skipped:
        console.print(f"[yellow]Skipping {name}: {reason}[/yellow]")

    correlation_run = run_correlate(scan_runs)

    resources_table = Table(title="Resources")
    resources_table.add_column("Key")
    resources_table.add_column("Refs")
    resources_table.add_column("Scanners")
    resources_table.add_column("Tags")
    for key, resource in correlation_run.resources.items():
        scanners_seen = ", ".join(sorted({ref.scanner for ref in resource.refs}))
        tags = ", ".join(f"{k}={v}" for k, v in resource.tags.items())
        resources_table.add_row(key, str(len(resource.refs)), scanners_seen, tags)
    console.print(resources_table)

    if correlation_run.clusters:
        clusters_table = Table(title="Clusters")
        clusters_table.add_column("Representative")
        clusters_table.add_column("Keys")
        clusters_table.add_column("Left")
        clusters_table.add_column("Right")
        clusters_table.add_column("Method")
        clusters_table.add_column("Confidence")
        for cluster in correlation_run.clusters:
            representative = str(cluster.representative())
            keys = ", ".join(sorted(str(k) for k in cluster.keys))
            for fact in cluster.facts:
                clusters_table.add_row(
                    representative,
                    keys,
                    str(fact.left),
                    str(fact.right),
                    fact.method,
                    f"{fact.confidence:g}",
                )
        console.print(clusters_table)

    findings_table = Table(title="Findings")
    findings_table.add_column("Finding")
    findings_table.add_column("Resource")
    findings_table.add_column("Confidence")
    for run in correlation_run.scan_runs:
        for finding in run.findings:
            finding_id = f"{finding.scanner}:{finding.rule_id}"
            for resolution in finding.resolutions:
                own_key = resolution.key
                findings_table.add_row(finding_id, str(own_key), f"{resolution.confidence:g}")
                cluster = next((c for c in correlation_run.clusters if own_key in c.keys), None)
                if cluster is None:
                    continue
                for other_key in sorted(cluster.keys, key=str):
                    if other_key == own_key:
                        continue
                    bridge_confidence = cluster.direct_confidence(own_key, other_key)
                    if bridge_confidence is None:
                        continue
                    eff = effective_confidence(finding, other_key, correlation_run)
                    findings_table.add_row(
                        finding_id,
                        str(other_key),
                        f"{eff:.3f} = {resolution.confidence:g} resolve x "
                        f"{bridge_confidence:g} bridge",
                    )
    console.print(findings_table)

    if correlation_run.tag_conflicts:
        conflicts_table = Table(title="Tag conflicts")
        conflicts_table.add_column("Resource")
        conflicts_table.add_column("Tag")
        conflicts_table.add_column("Values")
        for conflict in correlation_run.tag_conflicts:
            values = ", ".join(f"{scanner}={value}" for scanner, value in conflict.values)
            conflicts_table.add_row(str(conflict.resource_key), conflict.tag_key, values)
        console.print(conflicts_table)


if __name__ == "__main__":
    app()
