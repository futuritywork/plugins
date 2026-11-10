/**
 * Stateful MCP Server Example
 *
 * Demonstrates how to maintain state across tool calls.
 * This example uses a simple in-memory store.
 */

import { z } from "zod";
import { mcp } from "@futurity/plugins";
import { exampleManifest, examplePort } from "./config";

const Failure = z.object({ error: z.string(), key: z.string().optional() });

// Global state store
const state = {
	counter: 0,
	notes: [] as string[],
	kv: new Map<string, string>(),
};

const app = mcp({
	manifest: exampleManifest("stateful-server", "Stateful Server", "Counters, notes and a key-value store"),
	futurity: false,
	instructions: `This server demonstrates stateful operations.

Available tools:
- counter_increment: Increment the counter
- counter_decrement: Decrement the counter  
- counter_get: Get the current counter value
- counter_reset: Reset the counter to zero
- notes_add: Add a note
- notes_list: List all notes
- notes_clear: Clear all notes
- kv_set: Set a key-value pair
- kv_get: Get a value by key
- kv_delete: Delete a key
- kv_list: List all keys`,
});

// Counter tools
app.tool("counter_increment", {
	description: "Increment the counter by a specified amount",
	input: z.object({
		amount: z.number().default(1).describe("Amount to increment by"),
	}),
	output: z.object({ counter: z.number() }),
	handler: async ({ amount }) => {
		state.counter += amount;
		return { counter: state.counter };
	},
});

app.tool("counter_decrement", {
	description: "Decrement the counter by a specified amount",
	input: z.object({
		amount: z.number().default(1).describe("Amount to decrement by"),
	}),
	output: z.object({ counter: z.number() }),
	handler: async ({ amount }) => {
		state.counter -= amount;
		return { counter: state.counter };
	},
});

app.tool("counter_get", {
	description: "Get the current counter value",
	annotations: { readOnlyHint: true },
	output: z.object({ counter: z.number() }),
	handler: async () => {
		return { counter: state.counter };
	},
});

app.tool("counter_reset", {
	description: "Reset the counter to zero",
	output: z.object({ counter: z.number(), message: z.string() }),
	handler: async () => {
		state.counter = 0;
		return { counter: 0, message: "Counter reset" };
	},
});

// Notes tools
app.tool("notes_add", {
	description: "Add a new note",
	input: z.object({
		content: z.string().describe("The note content"),
	}),
	output: z.object({ message: z.string(), index: z.number(), totalNotes: z.number() }),
	handler: async ({ content }) => {
		state.notes.push(content);
		return {
			message: "Note added",
			index: state.notes.length - 1,
			totalNotes: state.notes.length,
		};
	},
});

app.tool("notes_list", {
	description: "List all notes",
	annotations: { readOnlyHint: true },
	output: z.object({ notes: z.array(z.object({ index: z.number(), content: z.string() })), count: z.number() }),
	handler: async () => {
		return {
			notes: state.notes.map((content, index) => ({ index, content })),
			count: state.notes.length,
		};
	},
});

app.tool("notes_delete", {
	description: "Delete a note by index",
	input: z.object({
		index: z.number().describe("The index of the note to delete"),
	}),
	output: z.union([z.object({ message: z.string(), deleted: z.string().optional() }), Failure]),
	handler: async ({ index }) => {
		if (index < 0 || index >= state.notes.length) {
			return { error: "Invalid index" };
		}
		const deleted = state.notes.splice(index, 1)[0];
		return { message: "Note deleted", deleted };
	},
});

app.tool("notes_clear", {
	description: "Clear all notes",
	output: z.object({ message: z.string() }),
	handler: async () => {
		const count = state.notes.length;
		state.notes = [];
		return { message: `Cleared ${count} notes` };
	},
});

// Key-Value store tools
app.tool("kv_set", {
	description: "Set a key-value pair",
	input: z.object({
		key: z.string().describe("The key"),
		value: z.string().describe("The value"),
	}),
	output: z.object({ key: z.string(), value: z.string(), action: z.enum(["updated", "created"]) }),
	handler: async ({ key, value }) => {
		const existed = state.kv.has(key);
		state.kv.set(key, value);
		return {
			key,
			value,
			action: existed ? "updated" : "created",
		};
	},
});

app.tool("kv_get", {
	description: "Get a value by key",
	annotations: { readOnlyHint: true },
	input: z.object({
		key: z.string().describe("The key to look up"),
	}),
	output: z.union([z.object({ key: z.string(), value: z.string().optional() }), Failure]),
	handler: async ({ key }) => {
		if (!state.kv.has(key)) {
			return { error: "Key not found", key };
		}
		return { key, value: state.kv.get(key) };
	},
});

app.tool("kv_delete", {
	description: "Delete a key-value pair",
	input: z.object({
		key: z.string().describe("The key to delete"),
	}),
	output: z.union([z.object({ message: z.string(), key: z.string() }), Failure]),
	handler: async ({ key }) => {
		if (!state.kv.has(key)) {
			return { error: "Key not found", key };
		}
		state.kv.delete(key);
		return { message: "Key deleted", key };
	},
});

app.tool("kv_list", {
	description: "List all key-value pairs",
	annotations: { readOnlyHint: true },
	output: z.object({ entries: z.array(z.object({ key: z.string(), value: z.string() })), count: z.number() }),
	handler: async () => {
		const entries = Array.from(state.kv.entries()).map(([key, value]) => ({
			key,
			value,
		}));
		return { entries, count: entries.length };
	},
});

// Status tool
app.tool("status", {
	description: "Get the current state summary",
	annotations: { readOnlyHint: true },
	output: z.object({ counter: z.number(), notesCount: z.number(), kvCount: z.number() }),
	handler: async () => {
		return {
			counter: state.counter,
			notesCount: state.notes.length,
			kvCount: state.kv.size,
		};
	},
});

app.listen(examplePort);
console.log(`Stateful MCP server running on http://localhost:${examplePort}/mcp`);
