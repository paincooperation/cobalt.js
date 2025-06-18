import { createHash, Hash, randomBytes } from "crypto";
import { createSocket, Socket } from "dgram";
import { exit } from "process";

export namespace cobalt {
	export type Serializer <T extends any = any> = (data: T) => Buffer<ArrayBufferLike>;
	export type Deserializer <T extends any = any> = (buffer: Buffer<ArrayBufferLike>) => T;
	export type ApiListener <T extends any, D extends any> = (remote: Remote<D>, data: T) => void;
	export type ID = string;

	export enum Signal {
		Connect = 37,			// Connection request
		Disconnect,			// Disconnection notification
	//	Challenge,			// Challenge of the ownership of the public key
	//	Verification,		// Verification of public key challenge
		Frame,				// Sending a frame
		LostFrame,
		Heartbeat,			// Signal hearbeat
	}

	export interface Api <T extends any, D extends any> {
		shard: Shard<D>;
		id: ID;

		listeners: Set<ApiListener<T, D>>;
		serializer: Serializer<T>;
		deserializer: Deserializer<T>;
		on: (listener: ApiListener<T, D>) => void;
		send: (remote: Remote<D>, data: T) => void;
	}

	export interface Remote <D extends any> {
		shard: Shard<D>;
		id: ID;

		address: string;
		port: number;
		data?: D;
	}

	export interface Transaction <T extends any, D extends any> {
		shard: Shard<D>;
		api: Api<T, D>;
		remote: Remote<D>;
		id: ID;

		data: T;
		framecount: bigint;
		frames: Map<bigint, Frame<T, D>>;
	}

	export interface Frame <T extends any, D extends any> {
		shard: Shard<D>;
		api: Api<T, D>;
		remote: Remote<D>;
		transaction: Transaction<T, D>;
		id: bigint;

		data: Buffer<ArrayBufferLike>;
		checksum: Buffer<ArrayBufferLike>;
	}

	export interface Shard <RemoteData extends any> {
		ipFamily: 4 | 6;
		socket: Socket;
		listen (address: string, port: number): void;
		close (): void;

		id: ID;

		serializer: Serializer;
		deserializer: Deserializer;
		api <T> (id: ID, serializer?: Serializer<T>, deserializer?: Deserializer<T>): Api<T, RemoteData>;
		apis: Map<ID, Api<any, RemoteData>>;
		remotes: Map<ID, Remote<RemoteData>>;
		connect: (address: string, port: number, remoteID: string | Buffer<ArrayBufferLike>) => void;

		inbound: Map<ID, Transaction<any, RemoteData>>;
		outbound: Map<ID, Transaction<any, RemoteData>>;
	}

	export function createShard <RemoteData extends any> (
		ipFamily?: Shard<RemoteData>["ipFamily"],
		id?: ID,
		serializer?: Serializer,
		deserializer?: Deserializer,
	) {
		let inboundchecker: NodeJS.Timeout;
		const shard = {} as Shard<RemoteData>;
		shard.ipFamily = ipFamily || 4;
		shard.socket = createSocket(`udp${shard.ipFamily}`);
		shard.listen = (address: string, port: number) => {
			shard.socket.bind(port, address);
			inboundchecker = setInterval(() => {
				shard.inbound.forEach((transaction) => {
					let now = 0;
					const missing = Array.from({length: Number(transaction.framecount)}, (v, i) => BigInt(i)).filter(v => !transaction.frames.has(v));
					for (let id of missing) {
						if (now > 1024) break;
						const fid = Buffer.alloc(8);
						fid.writeBigUInt64LE(id);
						shard.socket.send(Buffer.concat([
							Buffer.from([Signal.LostFrame]),
							Buffer.from(shard.id, "binary"),
							Buffer.from(transaction.remote.id, "binary"),
							Buffer.from(transaction.api.id, "binary"),
							Buffer.from(transaction.id, "binary"),
							fid,
						]), transaction.remote.port, transaction.remote.address);
						now++;
					}
				});
			}, 64);
		};
		shard.close = () => {
			clearTimeout(inboundchecker);
			shard.socket.close();
		};
		shard.id = (id || randomBytes(16).toString("binary")).slice(0, 16);
		shard.serializer = serializer || ((data: any) => Buffer.from(JSON.stringify(data), "binary"));
		shard.deserializer = deserializer || ((data: Buffer<ArrayBufferLike>) => JSON.parse(data.toString("binary")));
		shard.apis = new Map<ID, Api<any, RemoteData>>();
		shard.api = <T extends any> (
			id: ID,
			serializer?: Serializer,
			deserializer?: Deserializer,
		) => {
			const stableID = Buffer.alloc(16, 0);
			stableID.write(id.slice(0, 16), "binary");
			const api = {
				shard,
				id: stableID.toString("binary"),
				listeners: new Set(),
				serializer: serializer || shard.serializer,
				deserializer: deserializer || shard.deserializer,
				send: (remote, data) => {
					const transaction: Transaction<T, RemoteData> = {
						api,
						data,
						id: randomBytes(16).toString("binary"),
						remote,
						shard,
						frames: new Map(),
						framecount: 0n,
					};
					const raw = api.serializer(data);
					for (let id = 0n; id < raw.length; id += 1024n) {
						transaction.frames.set(id / 1024n, {
							api,
							id: id / 1024n,
							data: raw.subarray(Number(id), Number(id + 1024n)),
							remote,
							shard,
							transaction,
							checksum: createHash("sha256").update(raw.subarray(Number(id), Number(id + 1024n))).digest()
						});
						transaction.framecount++;
					}
					shard.outbound.set(transaction.id, transaction);
					const frame = transaction.frames.get(0n)!;
					const fid = Buffer.alloc(8);
					fid.writeBigUInt64LE(frame.id, 0);
					const fc = Buffer.alloc(8);
					fc.writeBigUInt64LE(transaction.framecount, 0);
					shard.socket.send(
						Buffer.concat([
							Buffer.from([Signal.Frame]),
							Buffer.from(shard.id, "binary"),
							Buffer.from(remote.id, "binary"),
							Buffer.from(api.id, "binary"),
							Buffer.from(transaction.id, "binary"),
							fid,
							fc,
							frame.checksum,
							frame.data,
						]),
						remote.port,
						remote.address,
					);
					setTimeout(() => {
						shard.outbound.delete(transaction.id);
					}, 30000);
				},
				on(listener) {
					api.listeners.add(listener);
				},
			} as Api<T, RemoteData>;
			shard.apis.set(stableID.toString("binary"), api);
			return api;
		};
		shard.remotes = new Map<ID, Remote<RemoteData>>();
		shard.inbound = new Map<ID, Transaction<any, RemoteData>>();
		shard.outbound = new Map<ID, Transaction<any, RemoteData>>();
		const inboundblocker = new Set<string>();
		shard.socket.on("message", (msg, rinfo) => {
			let counter = 1;
			const signal = msg[0] as Signal;

			if (signal === Signal.Connect) {
				const remoteID = msg.subarray(counter, counter += 16).toString("binary") as ID;
				const shardID = msg.subarray(counter, counter +=16).toString("binary") as ID;
				if (shard.id !== shardID) return;
				if (shard.remotes.has(remoteID)) return;
				const remote: Remote<RemoteData> = {
					address: rinfo.address,
					port: rinfo.port,
					data: void 0,
					id: remoteID,
					shard,
				}
				shard.remotes.set(remoteID, remote);
				shard.socket.send(Buffer.concat([Buffer.from([Signal.Connect]), Buffer.from(shard.id, "binary"), Buffer.from(remote.id, "binary")]), remote.port, remote.address);
				return;
			}

			if (signal === Signal.Disconnect) {
				const remoteID = msg.subarray(counter, counter += 16).toString("binary") as ID;
				const shardID = msg.subarray(counter, counter +=16).toString("binary") as ID;
				if (shard.id !== shardID) return;
				if (!shard.remotes.has(remoteID)) return;
				shard.remotes.delete(remoteID);
				shard.socket.send(Buffer.concat([Buffer.from([Signal.Disconnect]), Buffer.from(shard.id, "binary"), Buffer.from(remoteID, "binary")]));
				return;
			}

			if (signal === Signal.Heartbeat) {
				const remoteID = msg.subarray(counter, counter += 16).toString("binary") as ID;
				const shardID = msg.subarray(counter, counter +=16).toString("binary") as ID;
				if (shard.id !== shardID) return;
				if (!shard.remotes.has(remoteID)) return;
				const remote = shard.remotes.get(remoteID)!;
				if (remote.address !== rinfo.address || remote.port !== rinfo.port) return;
				setTimeout(() => {
					shard.socket.send(Buffer.concat([Buffer.from([Signal.Heartbeat]), Buffer.from(shard.id, "binary")]));
				}, 100);
				return;
			}

			if (signal === Signal.Frame) {
				const remoteID = msg.subarray(counter, counter += 16).toString("binary") as ID;
				const shardID = msg.subarray(counter, counter +=16).toString("binary") as ID;
				if (shard.id !== shardID || !shard.remotes.has(remoteID)) return;
				const apiID = msg.subarray(counter, counter += 16).toString("binary") as ID;
				const transactionID = msg.subarray(counter, counter += 16).toString("binary") as ID;
				const frameID =msg.subarray(counter, counter += 8).readBigInt64LE();
				const framecount = msg.subarray(counter, counter += 8).readBigInt64LE();
				const checksum = msg.subarray(counter, counter += 32);
				const frameData = msg.subarray(counter);

				const api = shard.apis.get(apiID);
				const remote = shard.remotes.get(remoteID);

				if (!api) return;
				if (!remote) return;

				if (!shard.inbound.has(transactionID) && !inboundblocker.has(transactionID)) shard.inbound.set(transactionID, {
					api: shard.apis.get(apiID)!,
					data: void 0 as any,
					framecount,
					frames: new Map(),
					id: transactionID,
					remote: shard.remotes.get(remoteID)!,
					shard,
				});

				const transaction = shard.inbound.get(transactionID)!;
				console.log("REC", [transaction.id], frameID, framecount);
				if (!createHash("sha256").update(frameData).digest().equals(checksum)) {
					const fid = Buffer.alloc(8);
					fid.writeBigUInt64LE(frameID, 0);
					shard.socket.send(Buffer.concat([
						Buffer.from([Signal.LostFrame]),
						Buffer.from(shardID, "binary"),
						Buffer.from(remoteID, "binary"),
						Buffer.from(apiID, "binary"),
						Buffer.from(transactionID, "binary"),
						fid,
					]));
					return;
				}

				transaction.frames.set(frameID, {
					shard,
					api,
					remote,
					checksum,
					data: frameData,
					id: frameID,
					transaction,
				});

				if (BigInt(transaction.frames.size) === transaction.framecount) {
					const full = Buffer.concat(Array.from(transaction.frames.keys()).sort().map(k => transaction.frames.get(k)!.data));
					const decoded = api.deserializer(full);
					transaction.api.listeners.forEach(listener => listener(remote, decoded));
					shard.inbound.delete(transaction.id);
					inboundblocker.add(transaction.id);
					setTimeout(() => {
						inboundblocker.delete(transaction.id);
					}, 3000);
					return;
				}

				return;
			}

			if (signal === Signal.LostFrame) {
				// this is an agro signal, dragons be here
				const remoteID = msg.subarray(counter, counter += 16).toString("binary") as ID;
				const shardID = msg.subarray(counter, counter +=16).toString("binary") as ID;
				if (shard.id !== shardID) return;
				if (!shard.remotes.has(remoteID)) return;
				const apiID = msg.subarray(counter, counter += 16).toString("binary") as ID;
				const transactionID = msg.subarray(counter, counter += 16).toString("binary") as ID;
				const frameID =msg.subarray(counter, counter += 8).readBigUInt64LE();
				
				const api = shard.apis.get(apiID);
				const remote = shard.remotes.get(remoteID);
				const transaction = shard.outbound.get(transactionID);
				if (!api || !remote || !transaction) return;
				
				const frame = transaction.frames.get(frameID);
				if (!frame) return;
				
				if (outboundframelostcache.has(frame)) return;
				outboundframelostcache.add(frame);
				
				const fid = Buffer.alloc(8);
				fid.writeBigUInt64LE(frame.id, 0);
				const fc = Buffer.alloc(8);
				fc.writeBigUInt64LE(transaction.framecount, 0);
				shard.socket.send(
					Buffer.concat([
						Buffer.from([Signal.Frame]),
						Buffer.from(shard.id, "binary"),
						Buffer.from(remote.id, "binary"),
						Buffer.from(api.id, "binary"),
						Buffer.from(transaction.id, "binary"),
						fid,
						fc,
						frame.checksum,
						frame.data,
					]),
					remote.port,
					remote.address,
				);
				console.log("RESENT", [transactionID], frameID);
				setTimeout(() => {
					outboundframelostcache.delete(frame);
				}, 500);
				return;
			}
		});
		const outboundframelostcache = new Set<Frame<any, RemoteData>>();
		const inboundframelostcache = new Set<string>();
		shard.connect = (address, port, remoteID) => {
			shard.socket.send(
				Buffer.concat([
					Buffer.from([Signal.Connect]),
					Buffer.from(shard.id, "binary"),
					typeof remoteID === "string"
						? Buffer.from(remoteID, "binary")
						: remoteID
				]),
				port,
				address,
			);
		};

		return shard;
	}
}

const server = cobalt.createShard(6);
server.listen("::", 3000);
const client = cobalt.createShard(6);
client.listen("::", 4040);

const server_api = server.api<any>("test");
const client_api = client.api<any>("test");

client.connect("::", 3000, server.id);

client_api.on((remote, data) => {
	console.clear();
	console.log("TRANSPORT RECIEVED", remote, data.length);
	exit(0);
});

setTimeout(() => {
	console.log(server.remotes);
	server.remotes.forEach(remote => {
		server_api.send(remote, bigshit);
	});
}, 700);


                // 32 BYTES                        32 KB        32MB
const bigshit = "THIS IS A VERY LONG STRING789012".repeat(1024).repeat(1024);