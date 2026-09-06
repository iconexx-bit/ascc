# VS Code extension inventory

Baselines for drift detection. Regenerate weekly, `git diff`, review.

| File | Host | Profile | Captured |
|---|---|---|---|
| vscode-ext-remote.txt | ai-sec-ubuntu (VM) | default | 2026-09-06 |
| vscode-ext-local.txt | Windows host | default | 2026-09-06 |
| vscode-ext-local-agents.txt | Windows host | Agents | 2026-09-06 |

Regenerate:
    code --list-extensions --show-versions | sort | grep -v '^Extensions installed'

## Policy
- Settings Sync: **Extensions disabled 2026-09-06** — extensions no longer
  replicate between hosts. Divergence between these files is expected.
- `extensions.autoUpdate: false` — versions here are pinned in practice.
- Anything not listed is drift. Investigate before accepting.

## 2026-09-06 audit
VM 35 → 15, Windows 41 → 36. Removed: 3 Copilot chat model providers
(Copilot Chat itself was never installed), 1 agentic AI extension with no
published ToS and arbitrary MCP server support, 13 unused Azure extensions
including an MCP server, 1 third-party auto-save, Go and Playwright.
Root cause of two-host replication: Settings Sync with Extensions enabled.
