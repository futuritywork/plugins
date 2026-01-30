/**
 * Virtual Filesystem MCP Server Example
 *
 * A simulated filesystem demonstrating:
 * - File and directory operations
 * - Path navigation
 * - File content management
 */

import { z } from "zod";
import { mcp } from "../src";
import { cors } from "../src/cors";

interface FsNode {
	type: "file" | "directory";
	name: string;
	content?: string;
	children?: Map<string, FsNode>;
	createdAt: Date;
	modifiedAt: Date;
	size: number;
}

// Virtual filesystem root
const root: FsNode = {
	type: "directory",
	name: "/",
	children: new Map(),
	createdAt: new Date(),
	modifiedAt: new Date(),
	size: 0,
};

// Current working directory
let cwd = "/";

// Helper to resolve path
function resolvePath(path: string): string {
	if (path.startsWith("/")) {
		return normalizePath(path);
	}
	return normalizePath(cwd + "/" + path);
}

function normalizePath(path: string): string {
	const parts = path.split("/").filter((p) => p && p !== ".");
	const result: string[] = [];

	for (const part of parts) {
		if (part === "..") {
			result.pop();
		} else {
			result.push(part);
		}
	}

	return "/" + result.join("/");
}

// Helper to get node at path
function getNode(path: string): FsNode | null {
	const resolved = resolvePath(path);
	if (resolved === "/") return root;

	const parts = resolved.split("/").filter(Boolean);
	let current = root;

	for (const part of parts) {
		if (current.type !== "directory" || !current.children?.has(part)) {
			return null;
		}
		current = current.children.get(part)!;
	}

	return current;
}

// Helper to get parent and name
function getParentAndName(path: string): { parent: FsNode | null; name: string } {
	const resolved = resolvePath(path);
	const parts = resolved.split("/").filter(Boolean);
	const name = parts.pop() || "";
	const parentPath = "/" + parts.join("/");
	return { parent: getNode(parentPath), name };
}

const app = mcp({
	name: "virtual-filesystem",
	version: "1.0.0",
	instructions: `A virtual filesystem server.

Tools:
- pwd: Print working directory
- cd: Change directory
- ls: List directory contents
- mkdir: Create directory
- touch: Create empty file
- write: Write content to file
- read: Read file content
- rm: Remove file or directory
- mv: Move/rename file or directory
- cp: Copy file
- find: Find files by name
- tree: Display directory tree`,
});

app.use(cors());

// pwd
app.tool("pwd", {
	description: "Print current working directory",
	handler: async () => ({ path: cwd }),
});

// cd
app.tool("cd", {
	description: "Change current directory",
	input: z.object({
		path: z.string().describe("Target directory path"),
	}),
	handler: async ({ path }) => {
		const resolved = resolvePath(path);
		const node = getNode(resolved);

		if (!node) {
			return { error: "Directory not found", path: resolved };
		}
		if (node.type !== "directory") {
			return { error: "Not a directory", path: resolved };
		}

		cwd = resolved;
		return { path: cwd };
	},
});

// ls
app.tool("ls", {
	description: "List directory contents",
	input: z.object({
		path: z.string().default(".").describe("Directory path"),
		all: z.boolean().default(false).describe("Show hidden files"),
	}),
	handler: async ({ path, all }) => {
		const node = getNode(path);

		if (!node) {
			return { error: "Path not found", path: resolvePath(path) };
		}
		if (node.type !== "directory") {
			return {
				entries: [
					{
						name: node.name,
						type: node.type,
						size: node.size,
					},
				],
			};
		}

		const entries = Array.from(node.children?.entries() || [])
			.filter(([name]) => all || !name.startsWith("."))
			.map(([name, child]) => ({
				name,
				type: child.type,
				size: child.size,
				modifiedAt: child.modifiedAt.toISOString(),
			}))
			.sort((a, b) => {
				if (a.type !== b.type) return a.type === "directory" ? -1 : 1;
				return a.name.localeCompare(b.name);
			});

		return { path: resolvePath(path), entries, count: entries.length };
	},
});

// mkdir
app.tool("mkdir", {
	description: "Create a directory",
	input: z.object({
		path: z.string().describe("Directory path to create"),
		parents: z.boolean().default(false).describe("Create parent directories if needed"),
	}),
	handler: async ({ path, parents }) => {
		const resolved = resolvePath(path);
		const parts = resolved.split("/").filter(Boolean);

		let current = root;
		for (let i = 0; i < parts.length; i++) {
			const part = parts[i]!;
			const isLast = i === parts.length - 1;

			if (!current.children) current.children = new Map();

			if (current.children.has(part)) {
				const existing = current.children.get(part)!;
				if (existing.type !== "directory") {
					return { error: "Path exists and is not a directory" };
				}
				if (isLast) {
					return { error: "Directory already exists" };
				}
				current = existing;
			} else {
				if (!isLast && !parents) {
					return { error: "Parent directory does not exist" };
				}
				const now = new Date();
				const newDir: FsNode = {
					type: "directory",
					name: part,
					children: new Map(),
					createdAt: now,
					modifiedAt: now,
					size: 0,
				};
				current.children.set(part, newDir);
				current = newDir;
			}
		}

		return { message: "Directory created", path: resolved };
	},
});

// touch
app.tool("touch", {
	description: "Create an empty file or update modification time",
	input: z.object({
		path: z.string().describe("File path"),
	}),
	handler: async ({ path }) => {
		const { parent, name } = getParentAndName(path);

		if (!parent || parent.type !== "directory") {
			return { error: "Parent directory not found" };
		}

		const now = new Date();
		if (parent.children?.has(name)) {
			const existing = parent.children.get(name)!;
			existing.modifiedAt = now;
			return { message: "File updated", path: resolvePath(path) };
		}

		if (!parent.children) parent.children = new Map();
		parent.children.set(name, {
			type: "file",
			name,
			content: "",
			createdAt: now,
			modifiedAt: now,
			size: 0,
		});

		return { message: "File created", path: resolvePath(path) };
	},
});

// write
app.tool("write", {
	description: "Write content to a file",
	input: z.object({
		path: z.string().describe("File path"),
		content: z.string().describe("File content"),
		append: z.boolean().default(false).describe("Append to existing content"),
	}),
	handler: async ({ path, content, append }) => {
		const { parent, name } = getParentAndName(path);

		if (!parent || parent.type !== "directory") {
			return { error: "Parent directory not found" };
		}

		if (!parent.children) parent.children = new Map();
		const now = new Date();

		if (parent.children.has(name)) {
			const existing = parent.children.get(name)!;
			if (existing.type !== "file") {
				return { error: "Path is a directory" };
			}
			existing.content = append ? (existing.content || "") + content : content;
			existing.size = existing.content.length;
			existing.modifiedAt = now;
		} else {
			parent.children.set(name, {
				type: "file",
				name,
				content,
				createdAt: now,
				modifiedAt: now,
				size: content.length,
			});
		}

		return {
			message: "File written",
			path: resolvePath(path),
			size: content.length,
		};
	},
});

// read
app.tool("read", {
	description: "Read file content",
	input: z.object({
		path: z.string().describe("File path"),
	}),
	handler: async ({ path }) => {
		const node = getNode(path);

		if (!node) {
			return { error: "File not found", path: resolvePath(path) };
		}
		if (node.type !== "file") {
			return { error: "Path is a directory" };
		}

		return {
			path: resolvePath(path),
			content: node.content || "",
			size: node.size,
		};
	},
});

// rm
app.tool("rm", {
	description: "Remove file or directory",
	input: z.object({
		path: z.string().describe("Path to remove"),
		recursive: z.boolean().default(false).describe("Remove directories recursively"),
	}),
	handler: async ({ path, recursive }) => {
		const { parent, name } = getParentAndName(path);

		if (!parent || !parent.children?.has(name)) {
			return { error: "Path not found" };
		}

		const node = parent.children.get(name)!;
		if (node.type === "directory" && node.children?.size && !recursive) {
			return { error: "Directory not empty (use recursive)" };
		}

		parent.children.delete(name);
		return { message: "Removed", path: resolvePath(path) };
	},
});

// tree
app.tool("tree", {
	description: "Display directory tree",
	input: z.object({
		path: z.string().default(".").describe("Root path"),
		depth: z.number().default(3).describe("Maximum depth"),
	}),
	handler: async ({ path, depth }) => {
		const node = getNode(path);
		if (!node) {
			return { error: "Path not found" };
		}

		function buildTree(n: FsNode, currentDepth: number): any {
			if (n.type === "file") {
				return { name: n.name, type: "file", size: n.size };
			}

			const result: any = { name: n.name, type: "directory", children: [] };
			if (currentDepth < depth && n.children) {
				for (const child of n.children.values()) {
					result.children.push(buildTree(child, currentDepth + 1));
				}
			} else if (n.children?.size) {
				result.children = `... ${n.children.size} items`;
			}
			return result;
		}

		return buildTree(node, 0);
	},
});

// find
app.tool("find", {
	description: "Find files by name pattern",
	input: z.object({
		path: z.string().default(".").describe("Search root"),
		name: z.string().describe("Name pattern (supports * wildcard)"),
	}),
	handler: async ({ path, name }) => {
		const node = getNode(path);
		if (!node) {
			return { error: "Path not found" };
		}

		const pattern = new RegExp(
			"^" + name.replace(/\*/g, ".*").replace(/\?/g, ".") + "$"
		);
		const results: string[] = [];

		function search(n: FsNode, currentPath: string) {
			if (pattern.test(n.name)) {
				results.push(currentPath);
			}
			if (n.type === "directory" && n.children) {
				for (const [childName, child] of n.children) {
					search(child, currentPath + "/" + childName);
				}
			}
		}

		const resolved = resolvePath(path);
		search(node, resolved === "/" ? "" : resolved);

		return { matches: results, count: results.length };
	},
});

app.listen(3000);
console.log("Virtual Filesystem MCP server running on http://localhost:3000/mcp");

