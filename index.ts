/**
 * guardrails — pre-execution safety layer for opencode.
 *
 * Combines original protections with cc-safety-net-inspired mechanics:
 *
 * 1. FORBIDDEN patterns  → thrown Error, blocks unconditionally.
 * 2. PROMPT patterns     → args tagged, opencode's permission system surfaces the intent.
 * 3. Shell-wrapper unwrap: `bash -c "…"`, `sh -c "…"`, `zsh -c "…"` — inner command
 *    is re-checked (defeats trivial evasion).
 * 4. Interpreter one-liners: `python -c "…"`, `node -e "…"`, `perl -e "…"`
 *    are flagged for approval (arbitrary code exec route).
 * 5. Pipe / `&&` / `||` / `;` split: each segment checked independently.
 * 6. Audit log: every block/prompt event appended to ~/.config/opencode/memory/guardrail.log.
 * 7. UI-preview reminder: cheap system-prompt injection for UI file paths.
 */

import type { Plugin } from "@opencode-ai/plugin"
import { appendFileSync, existsSync, mkdirSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

// --- config -----------------------------------------------------------------

const LOG_PATH = join(homedir(), ".config", "opencode", "memory", "guardrail.log")

/** Unconditional block. Fatal patterns that no user context justifies. */
const FORBIDDEN: Array<[RegExp, string]> = [
  // Trailing lookahead is (\s|$|['")]) instead of pure (\s|$) so patterns still
  // trigger inside quoted interpreter payloads, e.g. `os.system('rm -rf /')`.
  [/\brm\s+-rf?\s+\/(?=\s|$|['")])/, "rm -rf /"],
  [/\brm\s+-rf?\s+~\/?(?=\s|$|['")])/, "rm -rf ~"],
  [/\brm\s+-rf?\s+\*(?=\s|$|['")])/, "rm -rf *"],
  [/\brm\s+-rf?\s+\$HOME(?=\s|$|['")])/, "rm -rf $HOME"],
  [/\bmkfs\b/, "filesystem format"],
  [/\bdd\s+if=.*of=\/dev\/(disk|sda|nvme|hda)/, "raw disk write"],
  [/\bchmod\s+-R\s+777\s+\//, "chmod -R 777 /"],
  [/\bchown\s+-R\s+.+\s+\//, "chown -R … /"],
  [/>\s*\/dev\/(sda|nvme|hda|disk\d)/, "overwrite raw disk"],
]

/** Requires user prompt. Legitimate but destructive. */
const PROMPT: Array<[RegExp, string]> = [
  [/\bgit\s+push\s+.*(--force|-f\b)/, "git push --force"],
  [/\bgit\s+reset\s+--hard\b/, "git reset --hard"],
  [/\bgit\s+clean\s+-[a-z]*f/, "git clean -f"],
  [/\bgit\s+checkout\s+--\s+/, "git checkout -- (discards uncommitted work)"],
  [/\bgit\s+branch\s+-D\b/, "git branch -D (force delete)"],
  [/\bgit\s+stash\s+drop\b/, "git stash drop"],
  [/\bdrop\s+database\b/i, "SQL: drop database"],
  [/\btruncate\s+table\b/i, "SQL: truncate table"],
  [/\brm\s+-rf?\s+\.git\b/, "rm -rf .git"],
  [/\bsudo\b/, "sudo (privilege escalation)"],
]

/** Shell wrappers whose `-c` payload should be re-scanned. */
const SHELL_WRAPPER = /^\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh)\s+-l?c\s+/

/** Interpreter one-liners: arbitrary code execution vectors. */
const INTERPRETER_ONELINER = /^\s*(?:python3?|node|deno|ruby|perl|php|osascript)\s+-[ecm]\s+/

const UI_HINT = /\.(tsx|jsx|vue|svelte|astro|html|css|scss|sass|less)$|(^|\/)(components?|ui|views?|pages?|screens?|layouts?)\//i

const UI_SYSTEM_REMINDER =
  "UI/UX edit guardrail: before writing/editing UI code (.tsx/.jsx/.vue/.svelte/.astro/.html/.css or files under components|ui|views|pages|screens|layouts) that changes layout, hierarchy, or component structure, you MUST first emit an ASCII wireframe (before → after) and get one-line confirmation. See the ui-preview-first skill. Skip only for pure logic edits (handlers, hooks, style value tweaks) that don't move DOM nodes."

/**
 * Soft hint: bash commands using shell text tools where a dedicated opencode
 * tool would be faster/more deterministic. Never blocks — just injects a
 * one-liner into args so the model sees "you could have used Read/Grep/Glob".
 * Matches only when the tool name appears as an argv token (not e.g. `agent`).
 */
const SHELL_TEXT_TOOL_HINT = /(^|[\s;|&])(cat|head|tail|find|sed|awk|grep)(\s|$)/

// --- helpers ----------------------------------------------------------------

function extractQuoted(cmd: string): string | null {
  // Get the payload after `-c` for shell wrappers or `-e`/`-c` for interpreters.
  const m = cmd.match(/-[eEcm]\s+(?:'([^']*)'|"((?:[^"\\]|\\.)*)"|(\S+))/)
  if (!m) return null
  return m[1] ?? m[2] ?? m[3] ?? null
}

/** Patterns that MUST be checked on the raw un-split command (they span pipe/`&&` boundaries). */
const FORBIDDEN_WHOLE: Array<[RegExp, string]> = [
  [/:\(\)\s*\{.*:\|:.*\};:/, "fork bomb"],
  [/curl[^|]*\|\s*(sudo\s+)?(bash|sh|zsh)\b/, "curl | sh"],
  [/wget[^|]*\|\s*(sudo\s+)?(bash|sh|zsh)\b/, "wget | sh"],
]

/** Split on shell separators for independent evaluation. */
function segments(cmd: string): string[] {
  return cmd.split(/\s*(?:&&|\|\||;|\|(?!\|))\s*/).filter(Boolean)
}

function log(kind: "block" | "prompt", cmd: string, reason: string) {
  try {
    if (!existsSync(join(homedir(), ".config", "opencode", "memory"))) {
      mkdirSync(join(homedir(), ".config", "opencode", "memory"), { recursive: true })
    }
    appendFileSync(LOG_PATH, `${new Date().toISOString()}\t${kind}\t${reason}\t${cmd.slice(0, 400)}\n`)
  } catch {}
}

/** Recursively evaluate a command string. */
function evaluate(cmd: string, depth = 0): { action: "allow" | "prompt" | "block"; reason?: string } {
  if (depth > 4) return { action: "allow" } // safety valve against pathological nesting
  // Whole-string patterns first (fork bomb, curl|sh — these span pipe boundaries).
  for (const [re, reason] of FORBIDDEN_WHOLE) {
    if (re.test(cmd)) return { action: "block", reason }
  }
  // Whole-string FORBIDDEN scan — catches patterns hidden inside quoted
  // interpreter payloads that segment splitting would otherwise miss
  // (e.g. python3 -c "import os; os.system('rm -rf /')").
  for (const [re, reason] of FORBIDDEN) {
    if (re.test(cmd)) return { action: "block", reason }
  }
  for (const seg of segments(cmd)) {
    // Forbidden per segment — hard block.
    for (const [re, reason] of FORBIDDEN) {
      if (re.test(seg)) return { action: "block", reason }
    }
    // Shell wrapper unwrap.
    if (SHELL_WRAPPER.test(seg)) {
      const inner = extractQuoted(seg)
      if (inner) {
        const sub = evaluate(inner, depth + 1)
        if (sub.action !== "allow") return sub
      }
    }
    // Interpreter one-liner: recursively check the payload — a `python3 -c
    // "import os; os.system('rm -rf /')"` string must still hit FORBIDDEN.
    // Then fall through to prompt for legitimate one-liners.
    if (INTERPRETER_ONELINER.test(seg)) {
      const inner = extractQuoted(seg)
      if (inner) {
        const sub = evaluate(inner, depth + 1)
        if (sub.action === "block") return sub
      }
      return { action: "prompt", reason: `interpreter one-liner (${seg.split(/\s+/)[0]} -c/-e)` }
    }
    // Destructive-but-legit patterns.
    for (const [re, reason] of PROMPT) {
      if (re.test(seg)) return { action: "prompt", reason }
    }
  }
  return { action: "allow" }
}

// --- plugin -----------------------------------------------------------------

export const GuardrailsPlugin: Plugin = async () => {
  return {
    "tool.execute.before": async (input, output) => {
      if (input.tool === "bash") {
        const cmd: string = String(output.args?.command ?? "")
        if (!cmd) return
        const verdict = evaluate(cmd)
        if (verdict.action === "block") {
          log("block", cmd, verdict.reason ?? "")
          throw new Error(`[guardrails] refused: ${verdict.reason}. Command: ${cmd}`)
        }
        if (verdict.action === "prompt") {
          log("prompt", cmd, verdict.reason ?? "")
          output.args._guardrail_reason = `Destructive pattern: ${verdict.reason}. Confirm intent before running.`
        }
        // Soft nudge — never blocks. Encourages Read/Grep/Glob over shell text tools.
        if (SHELL_TEXT_TOOL_HINT.test(cmd)) {
          const existing = String(output.args._toolhint ?? "")
          const nudge = "Prefer dedicated opencode tools over shell text utilities: Read (not cat/head/tail), Grep (not grep), Glob (not find), Edit (not sed/awk), Write (not echo>>). See tool-call-discipline skill."
          output.args._toolhint = existing ? `${existing} | ${nudge}` : nudge
        }
      }
      if (input.tool === "edit" || input.tool === "write") {
        const path: string = String(output.args?.filePath ?? "")
        if (UI_HINT.test(path)) {
          output.args._ui_hint = "UI file — ASCII wireframe must precede this edit per guardrails."
        }
      }
    },

    "experimental.chat.system.transform": async (_input, output) => {
      output.system.push(UI_SYSTEM_REMINDER)
    },
  }
}

export default GuardrailsPlugin
