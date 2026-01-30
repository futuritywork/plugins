/**
 * monday.com MCP Server
 *
 * An MCP server that provides AI assistants with access to monday.com's API.
 * Auth is handled externally (e.g., by the Futurity API integration system)
 * and forwarded as a Bearer token on each request.
 *
 * Features:
 * - Board management (list, get details)
 * - Item CRUD operations
 * - Updates/comments
 * - Group management
 * - User info
 */

import { z } from "zod";
import { mcp, cors } from "../../src";
import type { PluginManifestOptions } from "../../src";
import {
	MondayClient,
	queries,
	mutations,
	type MondayBoard,
	type MondayItem,
	type MondayUser,
	type MondayUpdate,
} from "./client";

// ============================================================================
// Logging Helpers
// ============================================================================

function log(level: "info" | "debug" | "warn" | "error", message: string, data?: unknown) {
	const timestamp = new Date().toISOString();
	const prefix = `[${timestamp}] [monday-server] [${level.toUpperCase()}]`;
	if (data !== undefined) {
		console.log(`${prefix} ${message}`, JSON.stringify(data, null, 2));
	} else {
		console.log(`${prefix} ${message}`);
	}
}

function redactToken(token: string | null): string {
	if (!token) return "(null)";
	if (token.length <= 10) return "****";
	return token.slice(0, 6) + "..." + token.slice(-4);
}

// ============================================================================
// Per-request client using forwarded Bearer token
// ============================================================================

function extractToken(req: Request): string | null {
	const auth = req.headers.get("authorization");
	if (!auth?.startsWith("Bearer ")) {
		return null;
	}
	return auth.slice(7);
}

// ============================================================================
// Plugin Manifest (signed auth-forwarding declaration)
// ============================================================================

const signingKey = process.env.FUTURITY_SIGNING_KEY;
if (!signingKey) {
	console.error("FUTURITY_SIGNING_KEY environment variable is required");
	process.exit(1);
}

const port = parseInt(process.env.PORT || "3000", 10);
const baseUrl = process.env.BASE_URL || `http://localhost:${port}`;

const pluginManifest: PluginManifestOptions = {
	specVersion: 2,
	pluginId: "monday",
	name: "monday.com MCP Server",
	version: "1.0.0",
	signingKey,
	auth: {
		type: "forwarding",
		tokenEndpoint: "https://auth.monday.com/oauth2/token",
		authorizationEndpoint: "https://auth.monday.com/oauth2/authorize",
		requiredScopes: ["me:read", "boards:read", "boards:write", "workspaces:read", "updates:read", "updates:write"],
		deliveryMethod: "header",
	},
	mcpUrl: `${baseUrl}/mcp`,
};

// ============================================================================
// MCP Server Setup
// ============================================================================

const app = mcp({
	name: "monday-mcp",
	version: "1.0.0",
	pluginManifest,
	auth: async (req) => {
		const token = extractToken(req);
		if (!token) {
			log("warn", `Auth check FAILED: No token extracted`);
			return false;
		}

		try {
			const client = new MondayClient({ token });
			const result = await client.query<{ me: { id: string; name: string; email: string } }>(queries.me);
			log("info", `Token validated successfully for user: ${result.me.name} (${result.me.email})`);
			return true;
		} catch (error) {
			log("error", `Auth check FAILED: API validation error`, {
				error: error instanceof Error ? error.message : String(error),
			});
			return false;
		}
	},
	instructions: `A monday.com integration server that provides access to boards, items, and updates.
Auth is managed externally and forwarded as a Bearer token.

## Tools

### User & Account
- monday_me: Get current authenticated user info

### Boards
- monday_boards_list: List all accessible boards
- monday_board_get: Get board details including columns and groups

### Items (Tasks)
- monday_items_list: List items in a board with pagination
- monday_item_get: Get detailed item info including column values
- monday_item_create: Create a new item in a board
- monday_item_update: Update column values on an item
- monday_item_delete: Delete an item
- monday_item_archive: Archive an item
- monday_item_move: Move item to another group or board

### Updates (Comments)
- monday_updates_list: Get updates/comments on an item
- monday_update_create: Add a comment to an item

### Groups
- monday_group_create: Create a new group in a board
`,
});

app.use(cors());

// Store token per session
let currentToken: string | null = null;

app.middleware(async (req, next) => {
	const token = extractToken(req);
	if (token) {
		currentToken = token;
	}
	return next(req);
});

function getClient(): MondayClient {
	if (!currentToken) {
		throw new Error("Not authenticated - missing Bearer token");
	}
	return new MondayClient({ token: currentToken });
}

// ============================================================================
// User Tools
// ============================================================================

app.tool("monday_me", {
	description: "Get current authenticated user information including account details",
	handler: async () => {
		const client = getClient();
		const data = await client.query<{ me: MondayUser }>(queries.me);
		return {
			user: {
				id: data.me.id,
				name: data.me.name,
				email: data.me.email,
				title: data.me.title,
				photo: data.me.photo_thumb_small,
				account: data.me.account,
			},
		};
	},
});

// ============================================================================
// Board Tools
// ============================================================================

app.tool("monday_boards_list", {
	description: "List all accessible boards, ordered by most recently used",
	input: z.object({
		limit: z.number().min(1).max(100).default(25).describe("Number of boards to return"),
		page: z.number().min(1).default(1).describe("Page number for pagination"),
	}),
	handler: async ({ limit, page }) => {
		const client = getClient();
		const data = await client.query<{ boards: MondayBoard[] }>(queries.boards, { limit, page });
		return {
			boards: data.boards.map((b) => ({
				id: b.id,
				name: b.name,
				description: b.description,
				state: b.state,
				type: b.board_kind,
				itemsCount: b.items_count,
				workspace: b.workspace,
			})),
			count: data.boards.length,
			page,
		};
	},
});

app.tool("monday_board_get", {
	description: "Get detailed board information including columns and groups",
	input: z.object({
		boardId: z.string().describe("The board ID"),
	}),
	handler: async ({ boardId }) => {
		const client = getClient();
		const data = await client.query<{ boards: MondayBoard[] }>(queries.board, { id: boardId });

		const board = data.boards[0];
		if (!board) {
			return { error: "Board not found", boardId };
		}

		return {
			board: {
				id: board.id,
				name: board.name,
				description: board.description,
				state: board.state,
				type: board.board_kind,
				itemsCount: board.items_count,
				workspace: board.workspace,
				columns: board.columns?.map((c) => ({
					id: c.id,
					title: c.title,
					type: c.type,
					description: c.description,
				})),
				groups: board.groups?.map((g) => ({
					id: g.id,
					title: g.title,
					color: g.color,
				})),
			},
		};
	},
});

// ============================================================================
// Item Tools
// ============================================================================

app.tool("monday_items_list", {
	description: "List items in a board with pagination support",
	input: z.object({
		boardId: z.string().describe("The board ID"),
		limit: z.number().min(1).max(100).default(50).describe("Number of items to return"),
		cursor: z.string().optional().describe("Pagination cursor from previous response"),
		groupId: z.string().optional().describe("Filter by group ID"),
	}),
	handler: async ({ boardId, limit, cursor, groupId }) => {
		const client = getClient();
		const query = groupId ? queries.items : queries.itemsSimple;
		const variables = groupId ? { boardId, limit, cursor, groupId } : { boardId, limit, cursor };

		const data = await client.query<{
			boards: Array<{
				items_page: {
					cursor: string | null;
					items: MondayItem[];
				};
			}>;
		}>(query, variables);

		const page = data.boards[0]?.items_page;
		if (!page) {
			return { error: "Board not found", boardId };
		}

		return {
			items: page.items.map(formatItem),
			cursor: page.cursor,
			count: page.items.length,
		};
	},
});

app.tool("monday_item_get", {
	description: "Get detailed item information including all column values and subitems",
	input: z.object({
		itemId: z.string().describe("The item ID"),
	}),
	handler: async ({ itemId }) => {
		const client = getClient();
		const data = await client.query<{ items: MondayItem[] }>(queries.item, { id: itemId });

		const item = data.items[0];
		if (!item) {
			return { error: "Item not found", itemId };
		}

		return {
			item: {
				...formatItem(item),
				creator: item.creator,
				board: item.board,
				subitems: item.subitems?.map((s) => ({
					id: s.id,
					name: s.name,
					columns: formatColumnValues(s.column_values),
				})),
			},
		};
	},
});

app.tool("monday_item_create", {
	description: "Create a new item in a board",
	input: z.object({
		boardId: z.string().describe("The board ID"),
		name: z.string().describe("Item name"),
		groupId: z.string().optional().describe("Group ID (uses default group if not specified)"),
		columnValues: z
			.record(z.string(), z.unknown())
			.optional()
			.describe("Column values as JSON object (key: column_id, value: column value)"),
	}),
	handler: async ({ boardId, name, groupId, columnValues }) => {
		const client = getClient();
		const data = await client.query<{
			create_item: { id: string; name: string; group: { id: string; title: string } };
		}>(mutations.createItem, {
			boardId,
			groupId,
			itemName: name,
			columnValues: columnValues ? JSON.stringify(columnValues) : undefined,
		});

		return {
			message: "Item created",
			item: {
				id: data.create_item.id,
				name: data.create_item.name,
				group: data.create_item.group,
			},
		};
	},
});

app.tool("monday_item_update", {
	description: "Update column values on an item",
	input: z.object({
		boardId: z.string().describe("The board ID"),
		itemId: z.string().describe("The item ID"),
		columnValues: z
			.record(z.string(), z.unknown())
			.describe("Column values to update as JSON object (key: column_id, value: column value)"),
	}),
	handler: async ({ boardId, itemId, columnValues }) => {
		const client = getClient();
		const data = await client.query<{
			change_multiple_column_values: MondayItem;
		}>(mutations.updateItem, {
			boardId,
			itemId,
			columnValues: JSON.stringify(columnValues),
		});

		return {
			message: "Item updated",
			item: formatItem(data.change_multiple_column_values),
		};
	},
});

app.tool("monday_item_delete", {
	description: "Permanently delete an item",
	input: z.object({
		itemId: z.string().describe("The item ID to delete"),
	}),
	handler: async ({ itemId }) => {
		const client = getClient();
		await client.query<{ delete_item: { id: string } }>(mutations.deleteItem, { itemId });
		return { message: "Item deleted", itemId };
	},
});

app.tool("monday_item_archive", {
	description: "Archive an item (can be restored later)",
	input: z.object({
		itemId: z.string().describe("The item ID to archive"),
	}),
	handler: async ({ itemId }) => {
		const client = getClient();
		await client.query<{ archive_item: { id: string } }>(mutations.archiveItem, { itemId });
		return { message: "Item archived", itemId };
	},
});

app.tool("monday_item_move", {
	description: "Move an item to a different group or board",
	input: z.object({
		itemId: z.string().describe("The item ID to move"),
		targetBoardId: z.string().optional().describe("Target board ID (for cross-board moves)"),
		targetGroupId: z.string().describe("Target group ID"),
	}),
	handler: async ({ itemId, targetBoardId, targetGroupId }) => {
		const client = getClient();
		if (targetBoardId) {
			const data = await client.query<{
				move_item_to_board: { id: string; board: { id: string; name: string }; group: { id: string; title: string } };
			}>(mutations.moveItemToBoard, {
				itemId,
				boardId: targetBoardId,
				groupId: targetGroupId,
			});

			return {
				message: "Item moved to new board",
				item: {
					id: data.move_item_to_board.id,
					board: data.move_item_to_board.board,
					group: data.move_item_to_board.group,
				},
			};
		} else {
			const data = await client.query<{
				move_item_to_group: { id: string; group: { id: string; title: string } };
			}>(mutations.moveItemToGroup, {
				itemId,
				groupId: targetGroupId,
			});

			return {
				message: "Item moved to new group",
				item: {
					id: data.move_item_to_group.id,
					group: data.move_item_to_group.group,
				},
			};
		}
	},
});

// ============================================================================
// Update (Comment) Tools
// ============================================================================

app.tool("monday_updates_list", {
	description: "Get updates (comments) on an item",
	input: z.object({
		itemId: z.string().describe("The item ID"),
		limit: z.number().min(1).max(100).default(25).describe("Number of updates to return"),
	}),
	handler: async ({ itemId, limit }) => {
		const client = getClient();
		const data = await client.query<{
			items: Array<{ updates: MondayUpdate[] }>;
		}>(queries.updates, { itemId, limit });

		const updates = data.items[0]?.updates;
		if (!updates) {
			return { error: "Item not found", itemId };
		}

		return {
			updates: updates.map((u) => ({
				id: u.id,
				body: u.text_body || u.body,
				createdAt: u.created_at,
				creator: u.creator,
				replies: u.replies?.map((r) => ({
					id: r.id,
					body: r.text_body || r.body,
					createdAt: r.created_at,
					creator: r.creator,
				})),
			})),
		};
	},
});

app.tool("monday_update_create", {
	description: "Add a comment/update to an item",
	input: z.object({
		itemId: z.string().describe("The item ID"),
		body: z.string().describe("The update content (supports basic HTML formatting)"),
	}),
	handler: async ({ itemId, body }) => {
		const client = getClient();
		const data = await client.query<{
			create_update: MondayUpdate;
		}>(mutations.createUpdate, { itemId, body });

		return {
			message: "Update created",
			update: {
				id: data.create_update.id,
				body: data.create_update.text_body || data.create_update.body,
				createdAt: data.create_update.created_at,
			},
		};
	},
});

// ============================================================================
// Group Tools
// ============================================================================

app.tool("monday_group_create", {
	description: "Create a new group in a board",
	input: z.object({
		boardId: z.string().describe("The board ID"),
		name: z.string().describe("Group name"),
		color: z
			.string()
			.optional()
			.describe("Group color (e.g., #FF5AC4, #FDAB3D, #00C875, #0086C0)"),
	}),
	handler: async ({ boardId, name, color }) => {
		const client = getClient();
		const data = await client.query<{
			create_group: { id: string; title: string; color: string };
		}>(mutations.createGroup, {
			boardId,
			groupName: name,
			groupColor: color,
		});

		return {
			message: "Group created",
			group: {
				id: data.create_group.id,
				title: data.create_group.title,
				color: data.create_group.color,
			},
		};
	},
});

// ============================================================================
// Resources
// ============================================================================

app.resource("monday://me", {
	description: "Current authenticated user information",
	fetch: async () => {
		const client = getClient();
		const data = await client.query<{ me: MondayUser }>(queries.me);
		return {
			id: data.me.id,
			name: data.me.name,
			email: data.me.email,
			title: data.me.title,
			account: data.me.account,
		};
	},
});

app.resource("monday://boards", {
	description: "List of accessible boards",
	fetch: async () => {
		const client = getClient();
		const data = await client.query<{ boards: MondayBoard[] }>(queries.boards, {
			limit: 50,
			page: 1,
		});
		return data.boards.map((b) => ({
			id: b.id,
			name: b.name,
			description: b.description,
			type: b.board_kind,
			itemsCount: b.items_count,
		}));
	},
});

// ============================================================================
// Helpers
// ============================================================================

function formatColumnValues(columns?: Array<{ id: string; type: string; text?: string; value?: string }>) {
	if (!columns) return {};
	const result: Record<string, string | null> = {};
	for (const col of columns) {
		result[col.id] = col.text || null;
	}
	return result;
}

function formatItem(item: MondayItem) {
	return {
		id: item.id,
		name: item.name,
		state: item.state,
		createdAt: item.created_at,
		updatedAt: item.updated_at,
		group: item.group,
		columns: formatColumnValues(item.column_values),
	};
}

// ============================================================================
// Start Server
// ============================================================================

log("info", `=== SERVER STARTUP ===`);
log("info", `Plugin ID: ${pluginManifest.pluginId}`);
log("info", `Base URL: ${baseUrl}`);
log("info", `Port: ${port}`);

app.listen(port);
log("info", `monday.com MCP server running on ${baseUrl}/mcp`);
