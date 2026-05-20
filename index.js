import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { execFile } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_ID = "cat-agents-stability";
const PLUGIN_DIR = path.dirname(fileURLToPath(import.meta.url));

const READ_ACTIONS = new Set(["status", "snapshot", "policy", "lanes", "desired-state", "drift", "findings", "workflow-evidence", "actions", "events", "runbook"]);
const GUARDED_ACTIONS = new Set(["doctor", "repair", "once"]);

function jsonText(value) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(value, null, 2)
      }
    ]
  };
}

function objectConfig(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function pluginConfig(api) {
  return objectConfig(api?.pluginConfig || api?.config);
}

function boolConfig(value, fallback = false) {
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value === "boolean") return value;
  const text = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(text)) return true;
  if (["0", "false", "no", "n", "off"].includes(text)) return false;
  return Boolean(value);
}

function stabilityBin(api) {
  const configured = pluginConfig(api).stabilityBin;
  if (typeof configured === "string" && configured.trim()) return configured.trim();
  return path.join(PLUGIN_DIR, "bin", "cat-agents-stability");
}

function timeoutMs(api) {
  const configured = Number(pluginConfig(api).toolTimeoutMs || 30000);
  return Math.max(5000, Math.min(300000, Number.isFinite(configured) ? configured : 30000));
}

function runStability(api, args) {
  return new Promise((resolve) => {
    execFile(stabilityBin(api), args, {
      cwd: PLUGIN_DIR,
      timeout: timeoutMs(api),
      maxBuffer: 10 * 1024 * 1024,
      env: process.env
    }, (error, stdout, stderr) => {
      let parsed = null;
      try {
        parsed = stdout ? JSON.parse(stdout) : null;
      } catch {
        parsed = null;
      }
      resolve({
        ok: !error,
        command: [stabilityBin(api), ...args],
        status: error?.code ?? 0,
        signal: error?.signal || "",
        stdout: String(stdout || "").trim(),
        stderr: String(stderr || "").trim(),
        json: parsed,
        error: error ? String(error.message || error) : ""
      });
    });
  });
}

function stabilityArgs(api, params = {}) {
  const action = String(params.action || "status").trim();
  if (!READ_ACTIONS.has(action) && !GUARDED_ACTIONS.has(action)) throw new Error(`Unsupported cat-agents-stability action: ${action}`);
  const args = [action];
  if (action === "actions" && params.limit !== undefined) args.push("--limit", String(params.limit));
  if (action === "doctor" || action === "once") {
    const allowMutating = boolConfig(pluginConfig(api).allowMutatingActions, false);
    const noAction = params.noAction ?? params.no_action ?? !allowMutating;
    if (boolConfig(noAction, true)) args.push("--no-action");
  }
  if (action === "repair") {
    const allowMutating = boolConfig(pluginConfig(api).allowMutatingActions, false);
    const dryRun = params.dryRun ?? params.dry_run ?? !allowMutating;
    if (boolConfig(dryRun, true)) args.push("--dry-run");
  }
  return args;
}

const toolParameters = {
  type: "object",
  additionalProperties: false,
  properties: {
    action: {
      type: "string",
      enum: ["status", "snapshot", "policy", "lanes", "desired-state", "drift", "findings", "workflow-evidence", "actions", "events", "runbook", "doctor", "repair", "once"]
    },
    limit: { type: "number" },
    noAction: { type: "boolean" },
    no_action: { type: "boolean" },
    dryRun: { type: "boolean" },
    dry_run: { type: "boolean" }
  }
};

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "Cat Agents Stability",
  description: "Companion stability governance surface for trading-agents workflow, Gateway, Hermers, IM, cron, and session readiness.",
  contracts: {
    tools: ["cat_agents_stability"]
  },
  configSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      stabilityBin: { type: "string" },
      allowMutatingActions: { type: "boolean" },
      toolTimeoutMs: { type: "number" }
    }
  },
  register(api) {
    api.registerTool({
      name: "cat_agents_stability",
      description: "Read cat-agents stability status, desired-state drift, findings, lane policy, runbook, and guarded doctor/repair actions.",
      parameters: toolParameters,
      execute: async (_id, params) => jsonText(await runStability(api, stabilityArgs(api, params || {})))
    });
  }
});
