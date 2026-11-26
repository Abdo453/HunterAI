/**
 * Custom ESLint rule: `waitfor-budget`
 * Adapted cleanly from PentAGI's waitFor timeout discipline (MIT License,
 * retained in THIRD_PARTY_LICENSES/PENTAGI_MIT.txt) for Playwright E2E specs.
 *
 * Flags unbounded `waitFor*` calls (missing explicit `timeout`) and oversized
 * timeouts exceeding MAX_TIMEOUT_MS so flaky slow waits cannot creep into E2E suites.
 */

const WAIT_METHODS = new Set([
  "waitFor",
  "waitForSelector",
  "waitForFunction",
  "waitForResponse",
  "waitForRequest",
  "waitForEvent",
  "waitForLoadState",
  "waitForURL",
  "waitForTimeout",
]);

const DEFAULT_MAX_TIMEOUT_MS = 15000;

function extractTimeoutOption(node) {
  if (!node || node.type !== "ObjectExpression") return null;
  for (const prop of node.properties) {
    if (
      prop.type === "Property" &&
      ((prop.key.type === "Identifier" && prop.key.name === "timeout") ||
        (prop.key.type === "Literal" && prop.key.value === "timeout"))
    ) {
      if (prop.value.type === "Literal" && typeof prop.value.value === "number") {
        return prop.value.value;
      }
      return "dynamic";
    }
  }
  return null;
}

const waitforBudgetRule = {
  meta: {
    type: "problem",
    docs: {
      description: "Require bounded timeouts on Playwright waitFor* calls and disallow raw waitForTimeout sleeps",
    },
    schema: [
      {
        type: "object",
        properties: {
          maxTimeoutMs: { type: "number", minimum: 100 },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      noSleep: "Avoid fixed waitForTimeout() sleeps in E2E tests; wait on a deterministic assertion or event instead.",
      missingTimeout: "Playwright {{name}}() must pass an explicit { timeout } option within the test budget (<= {{max}}ms).",
      exceedsBudget: "Playwright {{name}}() timeout ({{actual}}ms) exceeds budget ({{max}}ms).",
    },
  },
  create(context) {
    const opts = context.options?.[0] || {};
    const maxTimeoutMs = typeof opts.maxTimeoutMs === "number" ? opts.maxTimeoutMs : DEFAULT_MAX_TIMEOUT_MS;

    return {
      CallExpression(node) {
        const callee = node.callee;
        if (!callee || callee.type !== "MemberExpression") return;
        const propName =
          callee.property.type === "Identifier"
            ? callee.property.name
            : callee.property.type === "Literal"
              ? String(callee.property.value)
              : "";
        if (!WAIT_METHODS.has(propName)) return;

        if (propName === "waitForTimeout") {
          context.report({ node, messageId: "noSleep" });
          return;
        }

        const args = node.arguments || [];
        const optionsArg = args.find((arg) => arg.type === "ObjectExpression");
        const timeoutVal = extractTimeoutOption(optionsArg);
        if (timeoutVal === null) {
          context.report({
            node,
            messageId: "missingTimeout",
            data: { name: propName, max: String(maxTimeoutMs) },
          });
        } else if (typeof timeoutVal === "number" && timeoutVal > maxTimeoutMs) {
          context.report({
            node,
            messageId: "exceedsBudget",
            data: { name: propName, actual: String(timeoutVal), max: String(maxTimeoutMs) },
          });
        }
      },
    };
  },
};

export default waitforBudgetRule;
