/**
 * monday.com GraphQL API Client
 *
 * A lightweight client for interacting with monday.com's GraphQL API.
 * Supports both API tokens and OAuth access tokens.
 */

const MONDAY_API_URL = "https://api.monday.com/v2";
const API_VERSION = "2025-04";

// Logging helpers
function redactToken(token: string): string {
	if (token.length <= 10) return "****";
	return token.slice(0, 6) + "..." + token.slice(-4);
}

function log(level: "info" | "debug" | "warn" | "error", message: string, data?: unknown) {
	const timestamp = new Date().toISOString();
	const prefix = `[${timestamp}] [monday-client] [${level.toUpperCase()}]`;
	if (data !== undefined) {
		console.log(`${prefix} ${message}`, JSON.stringify(data, null, 2));
	} else {
		console.log(`${prefix} ${message}`);
	}
}

export interface MondayClientOptions {
	token: string;
}

export interface MondayError {
	message: string;
	locations?: { line: number; column: number }[];
	path?: string[];
	extensions?: Record<string, unknown>;
}

export interface MondayResponse<T> {
	data?: T;
	errors?: MondayError[];
	account_id?: number;
}

export class MondayClient {
	private token: string;

	constructor(options: MondayClientOptions) {
		this.token = options.token;
		log("info", `MondayClient initialized with token: ${redactToken(options.token)}`);
	}

	async query<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
		const queryNameMatch = query.match(/(?:query|mutation)\s*(?:\(|{|\s)?\s*(\w+)?/);
		const queryName = queryNameMatch?.[1] || "anonymous";
		const operationType = query.trim().startsWith("mutation") ? "mutation" : "query";

		log("info", `Executing GraphQL ${operationType}: ${queryName}`);

		const requestBody = JSON.stringify({ query, variables });
		const startTime = Date.now();

		const response = await fetch(MONDAY_API_URL, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				Authorization: this.token,
				"API-Version": API_VERSION,
			},
			body: requestBody,
		});

		const elapsed = Date.now() - startTime;
		log("info", `Response received in ${elapsed}ms - Status: ${response.status}`);

		if (!response.ok) {
			const errorBody = await response.text();
			log("error", `HTTP error from monday.com API`, { status: response.status, body: errorBody });
			throw new Error(`monday.com API error: ${response.status} ${response.statusText}`);
		}

		const result = (await response.json()) as MondayResponse<T>;

		if (result.errors && result.errors.length > 0) {
			log("error", `GraphQL errors returned:`, result.errors);
			const errorMessages = result.errors.map((e) => e.message).join("; ");
			throw new Error(`GraphQL errors: ${errorMessages}`);
		}

		if (!result.data) {
			log("error", `No data in response`, result);
			throw new Error("No data returned from monday.com API");
		}

		log("info", `GraphQL ${operationType} ${queryName} completed successfully`);
		return result.data;
	}
}

// ============================================================================
// Types
// ============================================================================

export interface MondayUser {
	id: string;
	name: string;
	email: string;
	photo_thumb_small?: string;
	title?: string;
	account: {
		id: string;
		name: string;
	};
}

export interface MondayBoard {
	id: string;
	name: string;
	description?: string;
	state: "active" | "archived" | "deleted" | "all";
	board_kind: "public" | "private" | "share";
	workspace?: {
		id: string;
		name: string;
	};
	columns?: MondayColumn[];
	groups?: MondayGroup[];
	items_count?: number;
}

export interface MondayColumn {
	id: string;
	title: string;
	type: string;
	description?: string;
	settings_str?: string;
}

export interface MondayGroup {
	id: string;
	title: string;
	color: string;
	position?: string;
}

export interface MondayItem {
	id: string;
	name: string;
	state?: "active" | "archived" | "deleted";
	created_at?: string;
	updated_at?: string;
	creator?: {
		id: string;
		name: string;
	};
	board?: {
		id: string;
		name: string;
	};
	group?: {
		id: string;
		title: string;
	};
	column_values?: MondayColumnValue[];
	subitems?: MondayItem[];
}

export interface MondayColumnValue {
	id: string;
	type: string;
	text?: string;
	value?: string;
}

export interface MondayUpdate {
	id: string;
	body: string;
	text_body?: string;
	created_at: string;
	creator?: {
		id: string;
		name: string;
	};
	replies?: MondayUpdate[];
}

// ============================================================================
// GraphQL Queries
// ============================================================================

export const queries = {
	me: `
		query {
			me {
				id
				name
				email
				photo_thumb_small
				title
				account {
					id
					name
				}
			}
		}
	`,

	boards: `
		query($limit: Int, $page: Int) {
			boards(limit: $limit, page: $page, order_by: used_at) {
				id
				name
				description
				state
				board_kind
				items_count
				workspace {
					id
					name
				}
			}
		}
	`,

	board: `
		query($id: ID!) {
			boards(ids: [$id]) {
				id
				name
				description
				state
				board_kind
				items_count
				workspace {
					id
					name
				}
				columns {
					id
					title
					type
					description
				}
				groups {
					id
					title
					color
				}
			}
		}
	`,

	items: `
		query($boardId: ID!, $limit: Int, $cursor: String, $groupId: String) {
			boards(ids: [$boardId]) {
				items_page(limit: $limit, cursor: $cursor, query_params: { rules: [{ column_id: "group", compare_value: $groupId }] }) {
					cursor
					items {
						id
						name
						state
						created_at
						updated_at
						group {
							id
							title
						}
						column_values {
							id
							type
							text
							value
						}
					}
				}
			}
		}
	`,

	itemsSimple: `
		query($boardId: ID!, $limit: Int, $cursor: String) {
			boards(ids: [$boardId]) {
				items_page(limit: $limit, cursor: $cursor) {
					cursor
					items {
						id
						name
						state
						created_at
						updated_at
						group {
							id
							title
						}
						column_values {
							id
							type
							text
							value
						}
					}
				}
			}
		}
	`,

	item: `
		query($id: ID!) {
			items(ids: [$id]) {
				id
				name
				state
				created_at
				updated_at
				creator {
					id
					name
				}
				board {
					id
					name
				}
				group {
					id
					title
				}
				column_values {
					id
					type
					text
					value
				}
				subitems {
					id
					name
					column_values {
						id
						type
						text
					}
				}
			}
		}
	`,

	updates: `
		query($itemId: ID!, $limit: Int) {
			items(ids: [$itemId]) {
				updates(limit: $limit) {
					id
					body
					text_body
					created_at
					creator {
						id
						name
					}
					replies {
						id
						body
						text_body
						created_at
						creator {
							id
							name
						}
					}
				}
			}
		}
	`,
};

export const mutations = {
	createItem: `
		mutation($boardId: ID!, $groupId: String, $itemName: String!, $columnValues: JSON) {
			create_item(board_id: $boardId, group_id: $groupId, item_name: $itemName, column_values: $columnValues) {
				id
				name
				group {
					id
					title
				}
			}
		}
	`,

	updateItem: `
		mutation($boardId: ID!, $itemId: ID!, $columnValues: JSON!) {
			change_multiple_column_values(board_id: $boardId, item_id: $itemId, column_values: $columnValues) {
				id
				name
				column_values {
					id
					type
					text
					value
				}
			}
		}
	`,

	deleteItem: `
		mutation($itemId: ID!) {
			delete_item(item_id: $itemId) {
				id
			}
		}
	`,

	archiveItem: `
		mutation($itemId: ID!) {
			archive_item(item_id: $itemId) {
				id
			}
		}
	`,

	moveItemToGroup: `
		mutation($itemId: ID!, $groupId: String!) {
			move_item_to_group(item_id: $itemId, group_id: $groupId) {
				id
				group {
					id
					title
				}
			}
		}
	`,

	moveItemToBoard: `
		mutation($itemId: ID!, $boardId: ID!, $groupId: String) {
			move_item_to_board(item_id: $itemId, board_id: $boardId, group_id: $groupId) {
				id
				board {
					id
					name
				}
				group {
					id
					title
				}
			}
		}
	`,

	createUpdate: `
		mutation($itemId: ID!, $body: String!) {
			create_update(item_id: $itemId, body: $body) {
				id
				body
				text_body
				created_at
			}
		}
	`,

	createGroup: `
		mutation($boardId: ID!, $groupName: String!, $groupColor: String) {
			create_group(board_id: $boardId, group_name: $groupName, group_color: $groupColor) {
				id
				title
				color
			}
		}
	`,
};
