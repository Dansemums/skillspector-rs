# GitHub repository settings

Reference for the settings of https://github.com/Dansemums/skillspector-rs. The description, topics and discussions are already applied; the commands below are kept as documentation of what was set (they are not run by any script).

**Description**

> Optimized Rust port of NVIDIA SkillSpector: a fast static security scanner for AI agent skills (LLM features not included yet)

**Topics**

`agent-security`, `agent-skills`, `agentic-ai`, `ai-security`, `claude-code`, `mcp`, `prompt-injection`,
`security-scanner`, `security-tools`, `security-workflow`, `supply-chain-security`, `skillspector`,
`rust`, `rust-lang`, `static-analysis`, `cli`

(The first eleven are the topics of the upstream repository.)

**Other settings**

* Security: enable private vulnerability reporting and Dependabot alerts.
* Branch protection on `main`: require the `CI` workflow (both matrix jobs) to pass.
* Enable "Automatically delete head branches".

**Commands** (not run by any script; review first)

```bash
gh repo edit Dansemums/skillspector-rs \
  --add-topic agent-security --add-topic agent-skills --add-topic agentic-ai --add-topic ai-security \
  --add-topic claude-code --add-topic mcp --add-topic prompt-injection --add-topic security-scanner \
  --add-topic security-tools --add-topic security-workflow --add-topic supply-chain-security \
  --add-topic skillspector --add-topic rust --add-topic rust-lang --add-topic static-analysis --add-topic cli

# optional: labels used by .github/release.yml and the issue forms
for l in parity rules bug security robustness enhancement; do gh label create "$l" --repo Dansemums/skillspector-rs 2>/dev/null; done
```
