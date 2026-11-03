/**
 * ssh-exec.ts — 远程环境扩展：AI 的 bash 透明走远程
 *
 * 启动时自动从 ~/.ssh/my-ssh2.json 的 hosts 列表选择主机并建立 SSH 连接
 * （单台主机直接连接，多台主机弹框选择）。连接后：
 *
 *   内置 bash 被接管 — AI 的 shell 命令（ls/cat/grep/...）全部在远程执行，
 *   并把系统提示词里的 cwd 换成远程路径
 *
 * Usage:
 *   pi -e ./ssh-exec.ts
 *   /ssh-hosts   重新选择/切换主机
 *
 * 配置 ~/.ssh/my-ssh2.json：
 *   {
 *     "password": "全局默认密码",
 *     "hosts": [
 *       { "name": "生产", "target": "user@prod:/srv/app", "password": "可选" }
 *     ]
 *   }
 *
 * 认证顺序：主机 password → 全局 password → 私钥（显式配置或 ~/.ssh 默认私钥）→ ssh-agent。
 *
 * 依赖：
 *   - ssh2 (npm)
 */

import { Client } from "ssh2";
import { readFileSync } from "node:fs";
import { userInfo } from "node:os";
import { createBashTool, type BashOperations, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";

interface HostConfig {
	name?: string;
	target: string;
	password?: string;
	privateKey?: string;
	passphrase?: string;
}
interface SshConfig {
	password?: string;
	privateKey?: string;
	passphrase?: string;
	hosts?: HostConfig[];
}

const configPath = `${userInfo().homedir}/.ssh/my-ssh2.json`;

function loadConfig(): SshConfig | undefined {
	try {
		return JSON.parse(readFileSync(configPath, "utf8")) as SshConfig;
	} catch {
		/* 无配置文件或 JSON 非法 */
	}
	return undefined;
}

/** 解析 `user@host:/path`。 */
function parseTarget(arg: string): { remote: string; host: string; username: string; remoteCwd: string } {
	const colon = arg.indexOf(":");
	const remote = colon >= 0 ? arg.slice(0, colon) : arg;
	const at = remote.lastIndexOf("@");
	const username = at >= 0 ? remote.slice(0, at) : userInfo().username;
	const host = at >= 0 ? remote.slice(at + 1) : remote;
	return { remote, host, username, remoteCwd: colon >= 0 ? arg.slice(colon + 1) : "" };
}

/** 示例/占位密码：忽略，避免把示例文本当真密码发送。 */
const PLACEHOLDER_PASSWORDS = new Set(["可选", "optional", "全局默认密码", "password", "your-password", "your_password"]);

/** 过滤示例/占位密码，返回真正可用的密码。 */
function usablePassword(p: string | undefined): string | undefined {
	if (typeof p !== "string") return undefined;
	const t = p.trim();
	if (!t) return undefined;
	if (PLACEHOLDER_PASSWORDS.has(t.toLowerCase())) return undefined;
	return t;
}

/** 读取私钥文件（相对路径基于 ~/.ssh）。 */
function readKeyFile(p: string | undefined): Buffer | undefined {
	if (typeof p !== "string" || !p.trim()) return undefined;
	try {
		const abs = p.startsWith("/") ? p : `${userInfo().homedir}/.ssh/${p}`;
		const buf = readFileSync(abs);
		return buf.length ? buf : undefined;
	} catch {
		return undefined;
	}
}

/** 无显式配置时，回退到 ~/.ssh 下的常见默认私钥。 */
const DEFAULT_KEY_NAMES = ["id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"];

/** 执行远程命令，收集 stdout；非零退出码时 reject。 */
function runRemote(conn: Client, command: string): Promise<string> {
	return new Promise((resolve, reject) => {
		conn.exec(command, (err, stream) => {
			if (err) return reject(err);
			const out: Buffer[] = [];
			const errOut: Buffer[] = [];
			let code: number | null = null;
			let sig: string | undefined;
			stream.on("data", (d: Buffer) => out.push(d));
			stream.stderr.on("data", (d: Buffer) => errOut.push(d));
			stream.on("exit", ((c: number | null, s?: string) => {
				code = c;
				sig = s;
			}) as (c: number) => void);
			stream.on("close", () => {
				if (code === 0) resolve(Buffer.concat(out).toString());
				else reject(new Error(`SSH 命令失败 (${sig ? `signal ${sig}` : `exit ${code}`}): ${Buffer.concat(errOut).toString()}`));
			});
			stream.on("error", reject);
		});
	});
}

/** 把本地绝对路径映射到远程等价路径。 */
function makeToRemote(localCwd: string, remoteCwd: string): (p: string) => string {
	return (p: string) => (p.startsWith(localCwd) ? remoteCwd + p.slice(localCwd.length) : p);
}

/** 把 SSH 信号名映射为 POSIX 信号编号（BashOperations 要求 128 + 信号）。 */
function signalNumber(sig: string): number {
	const name = sig.replace(/^SIG/i, "").toUpperCase();
	const map: Record<string, number> = {
		HUP: 1, INT: 2, QUIT: 3, ILL: 4, TRAP: 5, ABRT: 6, BUS: 7, FPE: 8, KILL: 9,
		USR1: 10, SEGV: 11, USR2: 12, PIPE: 13, ALRM: 14, TERM: 15,
	};
	return map[name] ?? 15;
}

/** 流式执行远程命令，转发 stdout+stderr 到 onData，返回退出码。 */
function execRemote(
	conn: Client,
	command: string,
	opts: { onData: (data: Buffer) => void; signal?: AbortSignal; timeout?: number },
): Promise<{ exitCode: number | null }> {
	return new Promise((resolve, reject) => {
		conn.exec(command, (err, stream) => {
			if (err) return reject(err);
			let timedOut = false;
			let settled = false;
			let code: number | null = null;
			let sig: string | undefined;
			const timer = opts.timeout
				? setTimeout(() => {
						timedOut = true;
						try { stream.signal("KILL"); } catch { /* 通道已关闭 */ }
					}, opts.timeout * 1000)
				: undefined;
			stream.on("data", opts.onData);
			stream.stderr.on("data", opts.onData);
			const onAbort = () => {
				try { stream.signal("TERM"); } catch { /* 通道已关闭 */ }
			};
			opts.signal?.addEventListener("abort", onAbort, { once: true });
			stream.on("exit", ((c: number | null, s?: string) => {
				code = c;
				sig = s;
			}) as (c: number) => void);
			stream.on("close", () => {
				if (timer) clearTimeout(timer);
				opts.signal?.removeEventListener("abort", onAbort);
				if (settled) return;
				settled = true;
				if (opts.signal?.aborted) return reject(new Error("aborted"));
				if (timedOut) return reject(new Error(`timeout:${opts.timeout}`));
				resolve({ exitCode: sig ? 128 + signalNumber(sig) : code });
			});
			stream.on("error", (e: Error) => {
				if (timer) clearTimeout(timer);
				settled = true;
				reject(e);
			});
		});
	});
}

export default function (pi: ExtensionAPI) {
	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);

	let target: ReturnType<typeof parseTarget> | null = null;
	let client: Client | null = null;
	let connecting: Promise<Client> | null = null;
	let hostPassword: string | undefined;
	let hostPrivateKey: Buffer | undefined;
	let hostPassphrase: string | undefined;

	const resolvePassword = (): string | undefined => {
		const hostPw = usablePassword(hostPassword);
		if (hostPw) return hostPw;
		const cfg = loadConfig();
		return usablePassword(cfg?.password);
	};

	const resolvePassphrase = (): string | undefined => {
		const p = hostPassphrase ?? loadConfig()?.passphrase;
		return typeof p === "string" && p ? p : undefined;
	};

	const resolvePrivateKey = (): Buffer | undefined => {
		if (hostPrivateKey) return hostPrivateKey;
		const cfg = loadConfig();
		const globalKey = readKeyFile(cfg?.privateKey);
		if (globalKey) return globalKey;
		for (const name of DEFAULT_KEY_NAMES) {
			const k = readKeyFile(name);
			if (k) return k;
		}
		return undefined;
	};

	/** 返回共享的持久 SSH 连接（懒连接，断线自动重连）。 */
	const getClient = (): Promise<Client> => {
		if (!target) return Promise.reject(new Error("尚未连接远程主机"));
		if (client) return Promise.resolve(client);
		if (connecting) return connecting;
		connecting = new Promise<Client>((resolve, reject) => {
			const c = new Client();
			c.on("ready", () => {
				client = c;
				connecting = null;
				resolve(c);
			});
			c.on("error", (err) => {
				client = null;
				connecting = null;
				reject(err);
			});
			c.on("close", () => {
				client = null;
			});
			try {
				c.connect({
					host: target!.host,
					port: 22,
					username: target!.username,
					password: resolvePassword(),
					privateKey: resolvePrivateKey(),
					passphrase: resolvePassphrase(),
					agent: process.env.SSH_AUTH_SOCK || undefined,
					readyTimeout: 20_000,
					keepaliveInterval: 10_000,
				});
			} catch (e) {
				client = null;
				connecting = null;
				reject(e);
			}
		});
		return connecting;
	};

	/** 切换到指定主机并连接，解析远程工作目录。 */
	async function connectTo(hostTarget: string, ctx: ExtensionContext, hostCfg?: HostConfig): Promise<boolean> {
		client?.end();
		client = null;
		connecting = null;
		hostPassword = hostCfg?.password;
		hostPrivateKey = readKeyFile(hostCfg?.privateKey);
		hostPassphrase = hostCfg?.passphrase;
		target = parseTarget(hostTarget);
		try {
			const c = await getClient();
			if (!target.remoteCwd) {
				target.remoteCwd = (await runRemote(c, "pwd")).trim();
			}
			ctx.ui.setStatus("ssh", ctx.ui.theme.fg("accent", `SSH: ${target.remote}:${target.remoteCwd}`));
			ctx.ui.notify(`已连接: ${target.remote}:${target.remoteCwd}`, "info");
			return true;
		} catch (e) {
			ctx.ui.notify(`SSH 连接失败: ${(e as Error).message}`, "error");
			target = null;
			return false;
		}
	}

	const toRemote = (p: string) => (target ? makeToRemote(localCwd, target.remoteCwd)(p) : p);

	/** bash 工具的远程执行实现：cd 到远程映射路径后执行命令。 */
	function createRemoteBashOps(): BashOperations {
		return {
			exec: (command, cwd, opts) => {
				const cmd = `cd ${JSON.stringify(toRemote(cwd))} && ${command}`;
				return getClient().then((c) => execRemote(c, cmd, opts));
			},
		};
	}

	// 接管内置 bash：SSH 激活时 AI 的 shell 命令全部走远程，否则回退本地。
	pi.registerTool({
		...localBash,
		async execute(id, params, signal, onUpdate, _ctx) {
			if (target) {
				const tool = createBashTool(localCwd, { operations: createRemoteBashOps() });
				return tool.execute(id, params, signal, onUpdate);
			}
			return localBash.execute(id, params, signal, onUpdate);
		},
	});

	// /ssh-hosts：从配置 hosts 列表选择主机并连接（可随时切换）。
	pi.registerCommand("ssh-hosts", {
		description: "从 ~/.ssh/my-ssh2.json 的 hosts 列表选择主机并连接",
		async handler(_args, ctx) {
			if (!ctx.hasUI) {
				ctx.ui.notify("/ssh-hosts 需要交互界面", "error");
				return;
			}
			const hosts = (loadConfig()?.hosts ?? []).filter((h) => h && h.target);
			if (hosts.length === 0) {
				ctx.ui.notify("未找到主机：请在 ~/.ssh/my-ssh2.json 配置 hosts 数组", "error");
				return;
			}
			const options = hosts.map((h) => (h.name ? `${h.name}  (${h.target})` : h.target));
			const choice = await ctx.ui.select("选择要连接的远程主机", options);
			if (!choice) {
				ctx.ui.notify("已取消", "info");
				return;
			}
			const host = hosts[options.indexOf(choice)];
			if (host) await connectTo(host.target, ctx, host);
		},
	});


	// 把系统提示词里的本地 cwd 替换为远程 cwd，让 AI 感知远程工作目录。
	pi.on("before_agent_start", async (event) => {
		const t = target;
		if (t) {
			const modified = event.systemPrompt.replace(
				`Current working directory: ${localCwd}`,
				`Current working directory: ${t.remoteCwd} (via SSH: ${t.remote})`,
			);
			return { systemPrompt: modified };
		}
	});

	// 启动时自动从 hosts 列表选择并连接（单台直连，多台弹框）。
	pi.on("session_start", async (_event, ctx) => {
		const hosts = (loadConfig()?.hosts ?? []).filter((h) => h && h.target);
		if (hosts.length === 0) {
			if (ctx.hasUI) ctx.ui.notify("未在 ~/.ssh/my-ssh2.json 配置 hosts，可用 /ssh-hosts 补充配置后连接", "info");
			return;
		}
		// 单台主机：直接连接。
		if (hosts.length === 1) {
			await connectTo(hosts[0].target, ctx, hosts[0]);
			return;
		}
		// 多台主机：交互模式弹框选择，非交互模式提示。
		if (!ctx.hasUI) {
			ctx.ui.notify("检测到多台主机，非交互模式请配置单台主机或使用 /ssh-hosts", "info");
			return;
		}
		const options = hosts.map((h) => (h.name ? `${h.name}  (${h.target})` : h.target));
		const choice = await ctx.ui.select("选择要连接的远程主机", options);
		if (!choice) {
			ctx.ui.notify("未选择主机，可稍后用 /ssh-hosts 连接", "info");
			return;
		}
		const host = hosts[options.indexOf(choice)];
		if (host) await connectTo(host.target, ctx, host);
	});

	// 关闭持久连接。
	pi.on("session_shutdown", () => {
		client?.end();
		client = null;
		connecting = null;
		target = null;
		hostPassword = undefined;
		hostPrivateKey = undefined;
		hostPassphrase = undefined;
	});
}
