/**
 * In-Memory Database MCP Server Example
 *
 * A simple document database demonstrating:
 * - Collections and documents
 * - CRUD operations
 * - Querying and indexing
 */

import { z } from "zod";
import { mcp } from "../src";
import { cors } from "../src/cors";

// Document type
interface Document {
	_id: string;
	_collection: string;
	_createdAt: Date;
	_updatedAt: Date;
	[key: string]: unknown;
}

// In-memory storage
const collections = new Map<string, Map<string, Document>>();

// Generate unique ID
function generateId(): string {
	return crypto.randomUUID().replace(/-/g, "").slice(0, 24);
}

// Get or create collection
function getCollection(name: string): Map<string, Document> {
	if (!collections.has(name)) {
		collections.set(name, new Map());
	}
	return collections.get(name)!;
}

const app = mcp({
	name: "memory-database",
	version: "1.0.0",
	instructions: `An in-memory document database.

Collections:
- db_create_collection: Create a new collection
- db_list_collections: List all collections
- db_drop_collection: Drop a collection

Documents:
- db_insert: Insert a document
- db_insert_many: Insert multiple documents
- db_find_one: Find one document by query
- db_find: Find documents by query
- db_update: Update documents
- db_delete: Delete documents
- db_count: Count documents

Utilities:
- db_stats: Get database statistics`,
});

app.use(cors());

// Collection operations
app.tool("db_create_collection", {
	description: "Create a new collection",
	input: z.object({
		name: z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_]*$/).describe("Collection name"),
	}),
	handler: async ({ name }) => {
		if (collections.has(name)) {
			return { error: "Collection already exists", name };
		}
		collections.set(name, new Map());
		return { message: "Collection created", name };
	},
});

app.tool("db_list_collections", {
	description: "List all collections",
	handler: async () => {
		const list = Array.from(collections.entries()).map(([name, docs]) => ({
			name,
			documentCount: docs.size,
		}));
		return { collections: list, count: list.length };
	},
});

app.tool("db_drop_collection", {
	description: "Drop a collection and all its documents",
	input: z.object({
		name: z.string().describe("Collection name"),
	}),
	handler: async ({ name }) => {
		if (!collections.has(name)) {
			return { error: "Collection not found", name };
		}
		const count = collections.get(name)!.size;
		collections.delete(name);
		return { message: "Collection dropped", name, documentsDeleted: count };
	},
});

// Document operations
app.tool("db_insert", {
	description: "Insert a document into a collection",
	input: z.object({
		collection: z.string(),
		document: z.record(z.string(), z.unknown()),
	}),
	handler: async ({ collection, document }) => {
		const col = getCollection(collection);
		const now = new Date();
		const id = generateId();

		const doc: Document = {
			_id: id,
			_collection: collection,
			_createdAt: now,
			_updatedAt: now,
			...document,
		};

		col.set(id, doc);
		return { insertedId: id, document: formatDoc(doc) };
	},
});

app.tool("db_insert_many", {
	description: "Insert multiple documents",
	input: z.object({
		collection: z.string(),
		documents: z.array(z.record(z.string(), z.unknown())),
	}),
	handler: async ({ collection, documents }) => {
		const col = getCollection(collection);
		const now = new Date();
		const insertedIds: string[] = [];

		for (const document of documents) {
			const id = generateId();
			const doc: Document = {
				_id: id,
				_collection: collection,
				_createdAt: now,
				_updatedAt: now,
				...document,
			};
			col.set(id, doc);
			insertedIds.push(id);
		}

		return { insertedCount: insertedIds.length, insertedIds };
	},
});

app.tool("db_find_one", {
	description: "Find one document matching a query",
	input: z.object({
		collection: z.string(),
		query: z.record(z.string(), z.unknown()),
	}),
	handler: async ({ collection, query }) => {
		const col = getCollection(collection);
		
		for (const doc of col.values()) {
			if (matchesQuery(doc, query)) {
				return { document: formatDoc(doc) };
			}
		}

		return { document: null };
	},
});

app.tool("db_find", {
	description: "Find documents matching a query",
	input: z.object({
		collection: z.string(),
		query: z.record(z.string(), z.unknown()).default({}),
		limit: z.number().default(100),
		skip: z.number().default(0),
		sort: z.record(z.string(), z.enum(["asc", "desc"])).optional(),
	}),
	handler: async ({ collection, query, limit, skip, sort }) => {
		const col = getCollection(collection);
		let results = Array.from(col.values()).filter((doc) => matchesQuery(doc, query));

		// Sort
		if (sort) {
			const sortFields = Object.entries(sort);
			results.sort((a, b) => {
				for (const [field, order] of sortFields) {
					const aVal = a[field] as string | number;
					const bVal = b[field] as string | number;
					if (aVal < bVal) return order === "asc" ? -1 : 1;
					if (aVal > bVal) return order === "asc" ? 1 : -1;
				}
				return 0;
			});
		}

		// Paginate
		const total = results.length;
		results = results.slice(skip, skip + limit);

		return {
			documents: results.map(formatDoc),
			count: results.length,
			total,
		};
	},
});

app.tool("db_update", {
	description: "Update documents matching a query",
	input: z.object({
		collection: z.string(),
		query: z.record(z.string(), z.unknown()),
		update: z.record(z.string(), z.unknown()),
		multi: z.boolean().default(false),
	}),
	handler: async ({ collection, query, update, multi }) => {
		const col = getCollection(collection);
		let modifiedCount = 0;

		for (const doc of col.values()) {
			if (matchesQuery(doc, query)) {
				Object.assign(doc, update, { _updatedAt: new Date() });
				modifiedCount++;
				if (!multi) break;
			}
		}

		return { modifiedCount, matchedCount: modifiedCount };
	},
});

app.tool("db_delete", {
	description: "Delete documents matching a query",
	input: z.object({
		collection: z.string(),
		query: z.record(z.string(), z.unknown()),
		multi: z.boolean().default(false),
	}),
	handler: async ({ collection, query, multi }) => {
		const col = getCollection(collection);
		const toDelete: string[] = [];

		for (const doc of col.values()) {
			if (matchesQuery(doc, query)) {
				toDelete.push(doc._id);
				if (!multi) break;
			}
		}

		for (const id of toDelete) {
			col.delete(id);
		}

		return { deletedCount: toDelete.length };
	},
});

app.tool("db_count", {
	description: "Count documents matching a query",
	input: z.object({
		collection: z.string(),
		query: z.record(z.string(), z.unknown()).default({}),
	}),
	handler: async ({ collection, query }) => {
		const col = getCollection(collection);
		let count = 0;

		for (const doc of col.values()) {
			if (matchesQuery(doc, query)) {
				count++;
			}
		}

		return { count };
	},
});

// Stats
app.tool("db_stats", {
	description: "Get database statistics",
	handler: async () => {
		let totalDocuments = 0;
		const collectionStats: Record<string, number> = {};

		for (const [name, col] of collections) {
			collectionStats[name] = col.size;
			totalDocuments += col.size;
		}

		return {
			collections: collections.size,
			totalDocuments,
			collectionStats,
		};
	},
});

// Helper: check if document matches query
function matchesQuery(doc: Document, query: Record<string, unknown>): boolean {
	for (const [key, value] of Object.entries(query)) {
		if (key === "_id" && doc._id !== value) return false;
		if (key.startsWith("_")) continue;

		const docValue = doc[key] as string | number | boolean | null;

		// Handle comparison operators
		if (typeof value === "object" && value !== null) {
			const ops = value as Record<string, string | number | boolean | null>;
			if ("$gt" in ops && !(docValue! > ops.$gt!)) return false;
			if ("$gte" in ops && !(docValue! >= ops.$gte!)) return false;
			if ("$lt" in ops && !(docValue! < ops.$lt!)) return false;
			if ("$lte" in ops && !(docValue! <= ops.$lte!)) return false;
			if ("$ne" in ops && docValue === ops.$ne) return false;
			if ("$in" in ops && !Array.isArray(ops.$in)) return false;
			if ("$in" in ops && !(ops.$in as unknown[]).includes(docValue)) return false;
			if ("$regex" in ops) {
				const regex = new RegExp(ops.$regex as string, (ops.$options as string) || "");
				if (typeof docValue !== "string" || !regex.test(docValue)) return false;
			}
		} else {
			if (docValue !== value) return false;
		}
	}
	return true;
}

// Helper: format document for output
function formatDoc(doc: Document) {
	return {
		...doc,
		_createdAt: doc._createdAt.toISOString(),
		_updatedAt: doc._updatedAt.toISOString(),
	};
}

app.listen(3000);
console.log("Memory Database MCP server running on http://localhost:3000/mcp");

