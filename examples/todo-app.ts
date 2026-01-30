/**
 * Todo App MCP Server Example
 *
 * A complete todo list application demonstrating:
 * - CRUD operations
 * - Data validation with Zod
 * - Filtering and searching
 * - Resources for listing todos
 */

import { z } from "zod";
import { mcp } from "../src";
import { cors } from "../src/cors";

// Todo item type
interface Todo {
	id: string;
	title: string;
	description?: string;
	completed: boolean;
	priority: "low" | "medium" | "high";
	tags: string[];
	createdAt: Date;
	updatedAt: Date;
}

// In-memory todo store
const todos = new Map<string, Todo>();

// Generate unique ID
function generateId(): string {
	return crypto.randomUUID();
}

const app = mcp({
	name: "todo-app",
	version: "1.0.0",
	instructions: `A todo list management server.

Tools:
- todo_create: Create a new todo
- todo_get: Get a todo by ID
- todo_update: Update a todo
- todo_delete: Delete a todo
- todo_complete: Mark a todo as complete
- todo_uncomplete: Mark a todo as incomplete
- todo_list: List todos with optional filters
- todo_search: Search todos by title/description
- todo_stats: Get statistics about todos

Resources:
- todos://all - List all todos
- todos://pending - List pending todos
- todos://completed - List completed todos`,
});

app.use(cors());

// Create todo
app.tool("todo_create", {
	description: "Create a new todo item",
	input: z.object({
		title: z.string().min(1).describe("Todo title"),
		description: z.string().optional().describe("Optional description"),
		priority: z
			.enum(["low", "medium", "high"])
			.default("medium")
			.describe("Priority level"),
		tags: z.array(z.string()).default([]).describe("Tags for categorization"),
	}),
	handler: async ({ title, description, priority, tags }) => {
		const id = generateId();
		const now = new Date();
		const todo: Todo = {
			id,
			title,
			description,
			completed: false,
			priority,
			tags,
			createdAt: now,
			updatedAt: now,
		};
		todos.set(id, todo);
		return { message: "Todo created", todo: formatTodo(todo) };
	},
});

// Get todo
app.tool("todo_get", {
	description: "Get a todo by ID",
	input: z.object({
		id: z.string().describe("Todo ID"),
	}),
	handler: async ({ id }) => {
		const todo = todos.get(id);
		if (!todo) {
			return { error: "Todo not found", id };
		}
		return { todo: formatTodo(todo) };
	},
});

// Update todo
app.tool("todo_update", {
	description: "Update a todo item",
	input: z.object({
		id: z.string().describe("Todo ID"),
		title: z.string().min(1).optional().describe("New title"),
		description: z.string().optional().describe("New description"),
		priority: z.enum(["low", "medium", "high"]).optional().describe("New priority"),
		tags: z.array(z.string()).optional().describe("New tags"),
	}),
	handler: async ({ id, title, description, priority, tags }) => {
		const todo = todos.get(id);
		if (!todo) {
			return { error: "Todo not found", id };
		}

		if (title !== undefined) todo.title = title;
		if (description !== undefined) todo.description = description;
		if (priority !== undefined) todo.priority = priority;
		if (tags !== undefined) todo.tags = tags;
		todo.updatedAt = new Date();

		return { message: "Todo updated", todo: formatTodo(todo) };
	},
});

// Delete todo
app.tool("todo_delete", {
	description: "Delete a todo",
	input: z.object({
		id: z.string().describe("Todo ID"),
	}),
	handler: async ({ id }) => {
		if (!todos.has(id)) {
			return { error: "Todo not found", id };
		}
		todos.delete(id);
		return { message: "Todo deleted", id };
	},
});

// Complete todo
app.tool("todo_complete", {
	description: "Mark a todo as complete",
	input: z.object({
		id: z.string().describe("Todo ID"),
	}),
	handler: async ({ id }) => {
		const todo = todos.get(id);
		if (!todo) {
			return { error: "Todo not found", id };
		}
		todo.completed = true;
		todo.updatedAt = new Date();
		return { message: "Todo marked as complete", todo: formatTodo(todo) };
	},
});

// Uncomplete todo
app.tool("todo_uncomplete", {
	description: "Mark a todo as incomplete",
	input: z.object({
		id: z.string().describe("Todo ID"),
	}),
	handler: async ({ id }) => {
		const todo = todos.get(id);
		if (!todo) {
			return { error: "Todo not found", id };
		}
		todo.completed = false;
		todo.updatedAt = new Date();
		return { message: "Todo marked as incomplete", todo: formatTodo(todo) };
	},
});

// List todos with filters
app.tool("todo_list", {
	description: "List todos with optional filters",
	input: z.object({
		completed: z.boolean().optional().describe("Filter by completion status"),
		priority: z.enum(["low", "medium", "high"]).optional().describe("Filter by priority"),
		tag: z.string().optional().describe("Filter by tag"),
		limit: z.number().default(50).describe("Maximum number of todos to return"),
	}),
	handler: async ({ completed, priority, tag, limit }) => {
		let results = Array.from(todos.values());

		if (completed !== undefined) {
			results = results.filter((t) => t.completed === completed);
		}
		if (priority !== undefined) {
			results = results.filter((t) => t.priority === priority);
		}
		if (tag !== undefined) {
			results = results.filter((t) => t.tags.includes(tag));
		}

		results = results
			.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
			.slice(0, limit);

		return {
			todos: results.map(formatTodo),
			count: results.length,
			total: todos.size,
		};
	},
});

// Search todos
app.tool("todo_search", {
	description: "Search todos by title or description",
	input: z.object({
		query: z.string().describe("Search query"),
	}),
	handler: async ({ query }) => {
		const lowerQuery = query.toLowerCase();
		const results = Array.from(todos.values()).filter(
			(t) =>
				t.title.toLowerCase().includes(lowerQuery) ||
				t.description?.toLowerCase().includes(lowerQuery)
		);

		return {
			todos: results.map(formatTodo),
			count: results.length,
			query,
		};
	},
});

// Todo statistics
app.tool("todo_stats", {
	description: "Get statistics about todos",
	handler: async () => {
		const all = Array.from(todos.values());
		const completed = all.filter((t) => t.completed);
		const pending = all.filter((t) => !t.completed);

		const byPriority = {
			high: all.filter((t) => t.priority === "high").length,
			medium: all.filter((t) => t.priority === "medium").length,
			low: all.filter((t) => t.priority === "low").length,
		};

		const allTags = all.flatMap((t) => t.tags);
		const tagCounts = allTags.reduce(
			(acc, tag) => {
				acc[tag] = (acc[tag] || 0) + 1;
				return acc;
			},
			{} as Record<string, number>
		);

		return {
			total: all.length,
			completed: completed.length,
			pending: pending.length,
			completionRate:
				all.length > 0
					? Math.round((completed.length / all.length) * 100)
					: 0,
			byPriority,
			topTags: Object.entries(tagCounts)
				.sort((a, b) => b[1] - a[1])
				.slice(0, 5)
				.map(([tag, count]) => ({ tag, count })),
		};
	},
});

// Resources
app.resource("todos://all", {
	description: "All todos",
	fetch: async () => Array.from(todos.values()).map(formatTodo),
});

app.resource("todos://pending", {
	description: "Pending todos",
	fetch: async () =>
		Array.from(todos.values())
			.filter((t) => !t.completed)
			.map(formatTodo),
});

app.resource("todos://completed", {
	description: "Completed todos",
	fetch: async () =>
		Array.from(todos.values())
			.filter((t) => t.completed)
			.map(formatTodo),
});

// Helper to format todo for output
function formatTodo(todo: Todo) {
	return {
		id: todo.id,
		title: todo.title,
		description: todo.description,
		completed: todo.completed,
		priority: todo.priority,
		tags: todo.tags,
		createdAt: todo.createdAt.toISOString(),
		updatedAt: todo.updatedAt.toISOString(),
	};
}

app.listen(3000);
console.log("Todo App MCP server running on http://localhost:3000/mcp");

