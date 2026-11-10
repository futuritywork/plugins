import { describe, expect, test } from "bun:test";
import { toolDanger } from "./helpers";

describe("Tool danger from MCP annotations", () => {
  test("a tool marked read-only is a read", () => {
    const annotations = { readOnlyHint: true };

    const danger = toolDanger(annotations);

    expect(danger).toBe("read");
  });

  test("a tool marked both read-only and destructive is treated as a delete", () => {
    const annotations = { readOnlyHint: true, destructiveHint: true };

    const danger = toolDanger(annotations);

    expect(danger).toBe("delete");
  });

  test("a tool marked destructive is a delete", () => {
    const annotations = { readOnlyHint: false, destructiveHint: true };

    const danger = toolDanger(annotations);

    expect(danger).toBe("delete");
  });

  test.each([undefined, {}, { destructiveHint: false }, { readOnlyHint: false }])("a tool with annotations %j is a write", (annotations) => {
    const danger = toolDanger(annotations);

    expect(danger).toBe("write");
  });
});
