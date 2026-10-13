// Cross-implementation check for the MongoDB adapter: the TypeScript adapter shipped with
// better-auth 1.7.7 (@better-auth/mongo-adapter) writes rows into a database and reads rows
// written by the Go adapter (adapter/mongodb/compat_test.go drives this script).
//
// Usage: node scripts/mongo-compat.mjs <write|read>
// stdin:  {"uri": "...", "db": "...", "idMode": "default"|"uuid", ...command arguments}
// stdout: JSON result. Dates are rendered as ISO strings.
import { MongoClient } from "mongodb";
import { mongodbAdapter } from "better-auth/adapters/mongodb";

const command = process.argv[2];
const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const input = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");

const client = new MongoClient(input.uri);
await client.connect();
try {
	const db = client.db(input.db);
	const options = {
		rateLimit: { storage: "database" },
		advanced: {
			database: {
				joins: true,
				...(input.idMode === "uuid" ? { generateId: "uuid" } : {}),
			},
		},
	};
	const adapter = mongodbAdapter(db, { transaction: false })(options);

	if (command === "write") {
		const user = await adapter.create({
			model: "user",
			data: {
				name: "TS User",
				email: "ts@example.com",
				emailVerified: true,
				image: null,
				createdAt: new Date("2024-01-02T03:04:05.678Z"),
				updatedAt: new Date("2024-01-02T03:04:05.678Z"),
			},
		});
		const session = await adapter.create({
			model: "session",
			data: {
				userId: user.id,
				token: "ts-token",
				expiresAt: new Date("2030-01-01T00:00:00.000Z"),
				ipAddress: "127.0.0.1",
				createdAt: new Date("2024-01-02T03:04:05.678Z"),
				updatedAt: new Date("2024-01-02T03:04:05.678Z"),
			},
		});
		const account = await adapter.create({
			model: "account",
			data: {
				accountId: user.id,
				providerId: "credential",
				userId: user.id,
				password: "ts-hash",
				createdAt: new Date("2024-01-02T03:04:05.678Z"),
				updatedAt: new Date("2024-01-02T03:04:05.678Z"),
			},
		});
		const verification = await adapter.create({
			model: "verification",
			data: {
				identifier: "ts-identifier",
				value: "ts-value",
				expiresAt: new Date("2030-01-01T00:00:00.000Z"),
				createdAt: new Date("2024-01-02T03:04:05.678Z"),
				updatedAt: new Date("2024-01-02T03:04:05.678Z"),
			},
		});
		const rateLimit = await adapter.create({
			model: "rateLimit",
			data: { key: "ts-key", count: 1, lastRequest: 1700000000000 },
		});
		console.log(
			JSON.stringify({ user, session, account, verification, rateLimit }),
		);
	} else if (command === "read") {
		const user = await adapter.findOne({
			model: "user",
			where: [{ field: "id", value: input.userId }],
			join: { session: true, account: true },
		});
		const userByEmail = await adapter.findOne({
			model: "user",
			where: [{ field: "email", value: input.email.toUpperCase(), mode: "insensitive" }],
		});
		const sessions = await adapter.findMany({
			model: "session",
			where: [{ field: "userId", value: input.userId }],
		});
		const session = await adapter.findOne({
			model: "session",
			where: [{ field: "token", value: input.token }],
			join: { user: true },
		});
		const verification = await adapter.findOne({
			model: "verification",
			where: [{ field: "identifier", value: input.identifier }],
		});
		const rateLimit = await adapter.incrementOne({
			model: "rateLimit",
			where: [{ field: "key", value: input.rateLimitKey }],
			increment: { count: 1 },
		});
		const updated = await adapter.update({
			model: "user",
			where: [{ field: "id", value: input.userId }],
			update: { name: "Updated by TS" },
		});
		console.log(
			JSON.stringify({
				user,
				userByEmail,
				sessions,
				session,
				verification,
				rateLimit,
				updated,
			}),
		);
	} else {
		throw new Error(`unknown command ${command}`);
	}
} finally {
	await client.close();
}
