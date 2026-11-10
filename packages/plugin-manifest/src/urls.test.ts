import { describe, expect, test } from "bun:test";
import { manifest, option, problems } from "./fixtures";
import { FUTURITY_META_KEY } from "./schema";

const local = (url: string) => manifest(undefined, { remotes: [{ type: "streamable-http", url }] });

describe("Manifest URLs", () => {
  test("https URLs on the remote, icons, website and links are accepted", () => {
    const value = manifest(undefined, {
      icons: [{ src: "https://cdn.example.com/esb.png", mimeType: "image/png" }],
      websiteUrl: "https://esb.example.com",
    });
    value._meta[FUTURITY_META_KEY].listing = { links: { docs: "https://docs.example.com", privacy: "https://example.com/privacy" } };

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("an http remote on a public host is rejected", () => {
    const value = local("http://esb.example.com/mcp");

    const errors = problems(value);

    expect(errors).toEqual(["remotes[0].url: must use https"]);
  });

  test("an http icon is rejected", () => {
    const value = manifest(undefined, { icons: [{ src: "http://cdn.example.com/esb.png" }] });

    const errors = problems(value);

    expect(errors).toEqual(["icons[0].src: must use https"]);
  });

  test("a data URL icon is rejected", () => {
    const value = manifest(undefined, { icons: [{ src: "data:image/png;base64,AAAA" }] });

    const errors = problems(value);

    expect(errors).toEqual(["icons[0].src: must use https"]);
  });

  test("an http localhost remote is rejected in production", () => {
    const value = local("http://localhost:3000/mcp");

    const errors = problems(value);

    expect(errors).toEqual(["remotes[0].url: must use https"]);
  });

  test.each(["http://localhost:3000/mcp", "http://127.0.0.1:3000/mcp"])("the http localhost remote %s is accepted in development", (url) => {
    const value = local(url);

    const errors = problems(value, true);

    expect(errors).toEqual([]);
  });

  test("an http public remote is rejected in development", () => {
    const value = local("http://esb.example.com/mcp");

    const errors = problems(value, true);

    expect(errors).toEqual(["remotes[0].url: must use https (http only for localhost)"]);
  });

  test("a URL whose host is a placeholder is accepted when the scheme is literal", () => {
    const value = manifest([option({ fields: [{ key: "host", label: "Host", kind: "setup", scope: "install", input: "text", header: "X-Host" }] })], {
      remotes: [{ type: "streamable-http", url: "https://{host}/mcp" }],
    });

    const errors = problems(value);

    expect(errors).toEqual([]);
  });

  test("a URL that is only a placeholder is rejected because its scheme cannot be checked", () => {
    const value = manifest([option({ fields: [{ key: "base", label: "Base", kind: "setup", scope: "install", input: "text", header: "X-Base" }] })], {
      remotes: [{ type: "streamable-http", url: "{base}/mcp" }],
    });

    const errors = problems(value);

    expect(errors).toEqual(["remotes[0].url: must be an absolute URL"]);
  });
});
