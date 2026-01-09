---
name: conversation-retrospective
description: Analyzes the current conversation to suggest improvements to CLAUDE.md, documentation, setup, skills, hooks, or workflows. Use when the user asks for a retrospective, wants to improve their setup, or says "retro".
---

# Retrospective Analysis

Analyze the current conversation to identify issues, inefficiencies, or patterns that could be prevented or improved through updates to:

- **CLAUDE.md** - Project setup, common commands, code style guidelines
- **Documentation** - Project-specific guides or troubleshooting steps
- **Custom Skills** - Create new skills to automate recurring patterns
- **Hooks** - Prevent common mistakes automatically via hookify
- **Environment Setup** - Improve tooling configuration

## Instructions

### Step 1: Analyze the conversation

Review what happened in this conversation. Look for:

1. **Errors & mistakes**: Where did I struggle, make errors, or need multiple attempts?
2. **Missing context**: What did I need to ask about or look up that could have been in CLAUDE.md?
3. **Repetitive tasks**: Did we run similar commands repeatedly that could be documented?
4. **Setup friction**: Were there environment, dependency, or configuration issues?
5. **Preventable problems**: Could a hook or skill have avoided wasted time?

### Step 2: Generate specific suggestions

For each issue found, create a concrete improvement:

```markdown
## Issue: [Brief description]

**What happened:** [Describe the problem or inefficiency]

**Root cause:** [Why this happened - missing docs, no automation, etc.]

**Suggested fix:**

[Provide the EXACT content to add - a CLAUDE.md section, hook rule, skill file, etc.]

**Effort:** [Quick win / Medium / Complex]
```

### Step 3: Prioritize

Group suggestions by:
- **Quick wins** - 5 minutes or less, do immediately
- **Medium effort** - Worth doing but takes some time
- **Consider later** - Nice-to-have or complex

### Step 4: Offer to implement

After presenting suggestions, offer to:
1. Edit CLAUDE.md directly with approved changes
2. Create new skill files
3. Create hookify rules via `/hookify`
4. Update other documentation

## What NOT to suggest

- Don't suggest changes unrelated to actual conversation issues
- Don't over-engineer - keep suggestions simple and targeted
- Don't add documentation for one-off issues that won't recur
- Don't create skills/hooks for rare edge cases
