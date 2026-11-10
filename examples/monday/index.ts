/**
 * monday.com MCP Server
 *
 * An MCP server that provides AI assistants with access to monday.com's API.
 * Futurity runs the monday.com OAuth flow for each person and sends their
 * token in X-Monday-Token, next to a Futurity identity token the SDK verifies.
 *
 * Features:
 * - Board management (list, get details)
 * - Item CRUD operations
 * - Updates/comments
 * - Group management
 * - User info
 */

import { z } from "zod";
import { cors, FUTURITY_META_KEY, mcp, type FuturityIdentity, type PluginManifestInput } from "@futurity/plugins";
import {
	MondayClient,
	queries,
	mutations,
	type MondayBoard,
	type MondayItem,
	type MondayUser,
	type MondayUpdate,
} from "./client";

const Failure = z.object({ error: z.string(), boardId: z.string().optional(), itemId: z.string().optional() });
const Reference = z.object({ id: z.string(), name: z.string() });
const GroupRef = z.object({ id: z.string(), title: z.string() });
const Columns = z.record(z.string(), z.string().nullable());
const BoardSummary = z.object({
	id: z.string(),
	name: z.string(),
	description: z.string().optional(),
	state: z.enum(["active", "archived", "deleted", "all"]),
	type: z.enum(["public", "private", "share"]),
	itemsCount: z.number().optional(),
	workspace: Reference.optional(),
});
const Item = z.object({
	id: z.string(),
	name: z.string(),
	state: z.enum(["active", "archived", "deleted"]).optional(),
	createdAt: z.string().optional(),
	updatedAt: z.string().optional(),
	group: GroupRef.optional(),
	columns: Columns,
});
const Update = z.object({
	id: z.string(),
	body: z.string(),
	createdAt: z.string(),
	creator: Reference.optional(),
});

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

// ============================================================================
// Plugin Manifest
// ============================================================================

const port = parseInt(process.env.PORT || "3000", 10);
const baseUrl = process.env.BASE_URL || `http://localhost:${port}`;
const futurityUrl = process.env.FUTURITY_URL || "https://api-v4.futurity.work";

// Each person signs in to monday.com with the OAuth app the installing admin enters; Futurity runs the exchange.
// client "futurity" is only for marketplace plugins, whose OAuth app Futurity itself holds.
const manifest: PluginManifestInput = {
	name: "com.example/monday",
	title: "monday.com",
	description: "Boards, items, updates and groups in monday.com",
	version: "1.0.0",
	websiteUrl: "https://monday.com",
	remotes: [{ type: "streamable-http", url: `${baseUrl}/mcp` }],
	_meta: {
		[FUTURITY_META_KEY]: {
			specVersion: 5,
			developer: { email: "developer@example.com" },
			category: "productivity",
			credentials: [
				{
					id: "monday-oauth",
					label: "Sign in with monday.com",
					holder: "user",
					method: {
						type: "oauth",
						grant: "authorization_code",
						authorizationUrl: "https://auth.monday.com/oauth2/authorize",
						tokenUrl: "https://auth.monday.com/oauth2/token",
						scopes: ["me:read", "boards:read", "boards:write", "workspaces:read", "updates:read", "updates:write"],
						client: "install",
						delivery: { header: "X-Monday-Token" },
					},
					fields: [
						{ key: "client_id", label: "monday.com app client ID", kind: "setup", scope: "install", input: "text" },
						{ key: "client_secret", label: "monday.com app client secret", kind: "futurity_secret", scope: "install", input: "password" },
					],
				},
			],
		},
	},
};

// ============================================================================
// MCP Server Setup
// ============================================================================

const app = mcp({
	manifest,
	futurity: { issuers: [{ issuer: futurityUrl, jwksUrl: `${futurityUrl}/oauth/jwks` }] },
	instructions: `A monday.com integration server that provides access to boards, items, and updates.
Each caller's monday.com token arrives from Futurity with the request.

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

app.use(cors({ origins: [futurityUrl] }));

function getClient({ credentials }: FuturityIdentity): MondayClient {
	return new MondayClient({ token: credentials.access_token! });
}

// ============================================================================
// User Tools
// ============================================================================

app.tool("monday_me", {
	description: "Get current authenticated user information including account details",
	annotations: { readOnlyHint: true },
	output: z.object({
		user: z.object({
			id: z.string(),
			name: z.string(),
			email: z.string(),
			title: z.string().optional(),
			photo: z.string().optional(),
			account: Reference,
		}),
	}),
	handler: async (_input, ctx) => {
		const client = getClient(ctx);
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
	annotations: { readOnlyHint: true },
	input: z.object({
		limit: z.number().min(1).max(100).default(25).describe("Number of boards to return"),
		page: z.number().min(1).default(1).describe("Page number for pagination"),
	}),
	output: z.object({ boards: z.array(BoardSummary), count: z.number(), page: z.number() }),
	handler: async ({ limit, page }, ctx) => {
		const client = getClient(ctx);
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
	annotations: { readOnlyHint: true },
	input: z.object({
		boardId: z.string().describe("The board ID"),
	}),
	output: z.union([
		z.object({
			board: BoardSummary.extend({
				columns: z.array(z.object({ id: z.string(), title: z.string(), type: z.string(), description: z.string().optional() })).optional(),
				groups: z.array(GroupRef.extend({ color: z.string() })).optional(),
			}),
		}),
		Failure,
	]),
	handler: async ({ boardId }, ctx) => {
		const client = getClient(ctx);
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
	annotations: { readOnlyHint: true },
	input: z.object({
		boardId: z.string().describe("The board ID"),
		limit: z.number().min(1).max(100).default(50).describe("Number of items to return"),
		cursor: z.string().optional().describe("Pagination cursor from previous response"),
		groupId: z.string().optional().describe("Filter by group ID"),
	}),
	output: z.union([z.object({ items: z.array(Item), cursor: z.string().nullable(), count: z.number() }), Failure]),
	handler: async ({ boardId, limit, cursor, groupId }, ctx) => {
		const client = getClient(ctx);
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
	annotations: { readOnlyHint: true },
	input: z.object({
		itemId: z.string().describe("The item ID"),
	}),
	output: z.union([
		z.object({
			item: Item.extend({
				creator: Reference.optional(),
				board: Reference.optional(),
				subitems: z.array(z.object({ id: z.string(), name: z.string(), columns: Columns })).optional(),
			}),
		}),
		Failure,
	]),
	handler: async ({ itemId }, ctx) => {
		const client = getClient(ctx);
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
	output: z.object({ message: z.string(), item: z.object({ id: z.string(), name: z.string(), group: GroupRef }) }),
	handler: async ({ boardId, name, groupId, columnValues }, ctx) => {
		const client = getClient(ctx);
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
	output: z.object({ message: z.string(), item: Item }),
	handler: async ({ boardId, itemId, columnValues }, ctx) => {
		const client = getClient(ctx);
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
	annotations: { destructiveHint: true },
	input: z.object({
		itemId: z.string().describe("The item ID to delete"),
	}),
	output: z.object({ message: z.string(), itemId: z.string() }),
	handler: async ({ itemId }, ctx) => {
		const client = getClient(ctx);
		await client.query<{ delete_item: { id: string } }>(mutations.deleteItem, { itemId });
		return { message: "Item deleted", itemId };
	},
});

app.tool("monday_item_archive", {
	description: "Archive an item (can be restored later)",
	input: z.object({
		itemId: z.string().describe("The item ID to archive"),
	}),
	output: z.object({ message: z.string(), itemId: z.string() }),
	handler: async ({ itemId }, ctx) => {
		const client = getClient(ctx);
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
	output: z.object({ message: z.string(), item: z.object({ id: z.string(), board: Reference.optional(), group: GroupRef }) }),
	handler: async ({ itemId, targetBoardId, targetGroupId }, ctx) => {
		const client = getClient(ctx);
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
	annotations: { readOnlyHint: true },
	input: z.object({
		itemId: z.string().describe("The item ID"),
		limit: z.number().min(1).max(100).default(25).describe("Number of updates to return"),
	}),
	output: z.union([z.object({ updates: z.array(Update.extend({ replies: z.array(Update).optional() })) }), Failure]),
	handler: async ({ itemId, limit }, ctx) => {
		const client = getClient(ctx);
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
	output: z.object({ message: z.string(), update: z.object({ id: z.string(), body: z.string(), createdAt: z.string() }) }),
	handler: async ({ itemId, body }, ctx) => {
		const client = getClient(ctx);
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
	output: z.object({ message: z.string(), group: GroupRef.extend({ color: z.string() }) }),
	handler: async ({ boardId, name, color }, ctx) => {
		const client = getClient(ctx);
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
	fetch: async (ctx) => {
		const client = getClient(ctx);
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
	fetch: async (ctx) => {
		const client = getClient(ctx);
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
log("info", `Plugin: ${manifest.name}`);
log("info", `Base URL: ${baseUrl}`);
log("info", `Port: ${port}`);

app.listen(port);
log("info", `monday.com MCP server running on ${baseUrl}/mcp`);
