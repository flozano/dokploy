import {
	createHash,
	createPrivateKey,
	createPublicKey,
	createSign,
	generateKeyPairSync,
	type KeyObject,
	X509Certificate,
} from "node:crypto";
import { IS_CLOUD } from "@dokploy/server/constants";
import type { ociVaultConfigSchema } from "@dokploy/server/db/schema";
import type { z } from "zod";
import { type VaultClient, vaultFetch } from "./types";

type OciConfig = z.infer<typeof ociVaultConfigSchema>;
type ApiKeyConfig = Extract<OciConfig, { authType: "apiKey" }>;

type Method = "GET" | "POST";

interface Signer {
	keyId: string;
	key: KeyObject;
	principal: string;
	authFailureHint: string;
}

const INSTANCE_PRINCIPAL_ENV = "DOKPLOY_OCI_INSTANCE_PRINCIPAL";

const PAGE_SIZE = 100;
const MAX_LISTED_SECRETS = 500;
const SECRET_NAME_REGEX = /^[A-Za-z0-9._-]+$/;
const REGION_REGEX = /^[a-z0-9]+(-[a-z0-9]+)+$/;
const METADATA_URL = "http://169.254.169.254/opc/v2";
const METADATA_TIMEOUT_MS = 3_000;
const TOKEN_REFRESH_MARGIN_MS = 60_000;

const listNotFound = (signer: Signer) =>
	`the compartment or vault was not found, or ${signer.principal} is not allowed to list its secrets (requires "inspect secrets"). References can still resolve with only "read secret-bundles"`;

const secretsUrl = (config: OciConfig, path: string) =>
	new URL(
		`https://secrets.vaults.${config.region}.oci.oraclecloud.com/20190301${path}`,
	);

const vaultsUrl = (config: OciConfig, path: string) =>
	new URL(
		`https://vaults.${config.region}.oci.oraclecloud.com/20180608${path}`,
	);

/**
 * Refs are `name[:field]`. OCI secret names cannot contain `:`, so everything
 * after the first one is a key to extract from a JSON secret.
 */
const parseRef = (ref: string) => {
	const separatorIndex = ref.indexOf(":");
	const name = separatorIndex === -1 ? ref : ref.slice(0, separatorIndex);
	const field = separatorIndex === -1 ? null : ref.slice(separatorIndex + 1);
	if (!SECRET_NAME_REGEX.test(name) || field === "") {
		throw new Error(
			`Invalid OCI Vault reference "${ref}": expected <secret-name> or <secret-name>:<field>`,
		);
	}
	return { name, field };
};

const fingerprintOf = (key: KeyObject) =>
	createHash("md5")
		.update(createPublicKey(key).export({ type: "spki", format: "der" }))
		.digest("hex")
		.replace(/(..)(?!$)/g, "$1:");

const loadSigningKey = (config: ApiKeyConfig) => {
	let key: KeyObject;
	try {
		key = createPrivateKey({
			key: config.privateKey,
			format: "pem",
			passphrase: config.passphrase || undefined,
		});
	} catch (error) {
		throw new Error(
			`OCI Vault: cannot read the API private key, check the key and its passphrase (${error instanceof Error ? error.message : "invalid key"})`,
		);
	}
	if (key.asymmetricKeyType !== "rsa") {
		throw new Error("OCI Vault: the API private key must be an RSA key");
	}
	// A mismatched fingerprint only surfaces as an opaque 401 from OCI.
	const fingerprint = fingerprintOf(key);
	if (fingerprint !== config.fingerprint.toLowerCase()) {
		throw new Error(
			`OCI Vault: the fingerprint does not match the private key (the key's fingerprint is ${fingerprint})`,
		);
	}
	return key;
};

const signedHeaders = (
	signer: Signer,
	method: Method,
	url: URL,
	body: string,
) => {
	const headers: Record<string, string> = {
		"x-date": new Date().toUTCString(),
	};
	// fetch derives host and content-length itself and ignores explicit values,
	// so they are signed with what it sends but never set here.
	const signed: [string, string][] = [
		["x-date", headers["x-date"] as string],
		[
			"(request-target)",
			`${method.toLowerCase()} ${url.pathname}${url.search}`,
		],
		["host", url.host],
	];
	if (method === "POST") {
		const contentSha256 = createHash("sha256").update(body).digest("base64");
		headers["content-type"] = "application/json";
		headers["x-content-sha256"] = contentSha256;
		signed.push(
			["content-type", "application/json"],
			["content-length", String(Buffer.byteLength(body))],
			["x-content-sha256", contentSha256],
		);
	}

	const signature = createSign("RSA-SHA256")
		.update(signed.map(([name, value]) => `${name}: ${value}`).join("\n"))
		.sign(signer.key, "base64");
	headers.authorization = `Signature version="1",keyId="${signer.keyId}",algorithm="rsa-sha256",headers="${signed.map(([name]) => name).join(" ")}",signature="${signature}"`;
	return headers;
};

const request = async (
	signer: Signer,
	method: Method,
	url: URL,
	notFoundMessage: string,
	body = "",
) => {
	const response = await vaultFetch(url.toString(), {
		method,
		headers: {
			...signedHeaders(signer, method, url, body),
			Accept: "application/json",
		},
		...(method === "POST" && { body }),
	});

	if (response.ok) {
		return response;
	}

	let detail = "";
	try {
		const body = (await response.json()) as { code?: string; message?: string };
		detail = [body.code, body.message].filter(Boolean).join(": ");
	} catch {}
	const requestId = response.headers.get("opc-request-id");
	const status = `status ${response.status}${detail ? `: ${detail}` : ""}${requestId ? `, opc-request-id ${requestId}` : ""}`;

	if (response.status === 401) {
		throw new Error(
			`OCI Vault: authentication failed (${status}). ${signer.authFailureHint}`,
		);
	}
	// OCI answers 404 both when a resource is missing and when access is denied.
	if (response.status === 404) {
		throw new Error(`OCI Vault: ${notFoundMessage} (${status})`);
	}
	throw new Error(`OCI Vault: request failed (${status})`);
};

const readSecret = async (config: OciConfig, signer: Signer, name: string) => {
	const url = secretsUrl(config, "/secretbundles/actions/getByName");
	url.search = new URLSearchParams({
		secretName: name,
		vaultId: config.vaultId,
	}).toString();
	const response = await request(
		signer,
		"POST",
		url,
		`secret "${name}" not found in the vault, or ${signer.principal} is not allowed to read it (requires "read secret-bundles")`,
	);

	const bundle = (await response.json()) as {
		secretBundleContent?: { contentType?: string; content?: string };
	};
	const content = bundle.secretBundleContent;
	if (content?.content === undefined) {
		throw new Error(`OCI Vault: secret "${name}" has no content`);
	}
	if (content.contentType !== "BASE64") {
		throw new Error(
			`OCI Vault: secret "${name}" has unsupported content type "${content.contentType}"`,
		);
	}
	try {
		// Keep the default ignoreBOM: false. A leading BOM marks the encoding rather
		// than being part of the value, and JSON.parse would reject it.
		return new TextDecoder("utf-8", { fatal: true }).decode(
			Buffer.from(content.content, "base64"),
		);
	} catch {
		throw new Error(
			`OCI Vault: secret "${name}" is not UTF-8 text (binary secrets are not supported)`,
		);
	}
};

const listUrl = (config: OciConfig, limit: number, page?: string) => {
	const url = vaultsUrl(config, "/secrets");
	url.search = new URLSearchParams({
		compartmentId: config.compartmentId,
		vaultId: config.vaultId,
		lifecycleState: "ACTIVE",
		sortBy: "NAME",
		sortOrder: "ASC",
		limit: String(limit),
		...(page && { page }),
	}).toString();
	return url;
};

const fetchMetadata = async (path: string) => {
	let response: Response;
	try {
		response = await fetch(`${METADATA_URL}/${path}`, {
			headers: { Authorization: "Bearer Oracle" },
			signal: AbortSignal.timeout(METADATA_TIMEOUT_MS),
		});
	} catch {
		throw new Error(
			"OCI Vault: cannot reach the instance metadata service. Instance principal authentication only works when Dokploy runs on an OCI compute instance",
		);
	}
	if (!response.ok) {
		throw new Error(
			`OCI Vault: the instance metadata service answered status ${response.status} for ${path}`,
		);
	}
	return (await response.text()).trim();
};

const tokenExpiry = (token: string) => {
	let exp: unknown;
	try {
		exp = JSON.parse(
			Buffer.from(token.split(".")[1] ?? "", "base64url").toString(),
		).exp;
	} catch {}
	if (typeof exp !== "number") {
		throw new Error("OCI Vault: the auth service returned an unreadable token");
	}
	return exp * 1000;
};

// Mirrors the OCI SDKs: the instance certificate from the metadata service is
// exchanged for a short-lived token bound to a fresh session key.
const createSession = async () => {
	const [certificatePem, certificateKeyPem, intermediatePem, region] =
		await Promise.all([
			fetchMetadata("identity/cert.pem"),
			fetchMetadata("identity/key.pem"),
			fetchMetadata("identity/intermediate.pem"),
			fetchMetadata("instance/canonicalRegionName"),
		]);
	if (!REGION_REGEX.test(region)) {
		throw new Error(
			`OCI Vault: unexpected region "${region}" from the instance metadata service`,
		);
	}
	const certificate = new X509Certificate(certificatePem);
	const tenancyId = certificate.subject.match(
		/opc-(?:tenant|identity):([^\s,]+)/,
	)?.[1];
	if (!tenancyId) {
		throw new Error(
			"OCI Vault: the instance certificate does not name a tenancy",
		);
	}

	const sessionKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const body = JSON.stringify({
		certificate: certificate.raw.toString("base64"),
		publicKey: sessionKey.publicKey
			.export({ type: "spki", format: "der" })
			.toString("base64"),
		intermediateCertificates: [
			new X509Certificate(intermediatePem).raw.toString("base64"),
		],
		purpose: "DEFAULT",
	});
	const response = await request(
		{
			// The auth service identifies the certificate by its SHA-1 fingerprint.
			keyId: `${tenancyId}/fed-x509/${certificate.fingerprint.toLowerCase()}`,
			key: createPrivateKey(certificateKeyPem),
			principal: "this instance",
			authFailureHint: "The auth service rejected the instance certificate",
		},
		"POST",
		new URL(`https://auth.${region}.oraclecloud.com/v1/x509`),
		"the auth service endpoint was not found",
		body,
	);
	const { token } = (await response.json()) as { token?: string };
	if (!token) {
		throw new Error("OCI Vault: the auth service returned no token");
	}
	return {
		signer: {
			keyId: `ST$${token}`,
			key: sessionKey.privateKey,
			principal: "this instance",
			authFailureHint:
				"The instance principal token was rejected; check that the server clock is correct",
		} satisfies Signer,
		expiresAt: tokenExpiry(token),
	};
};

let session: Awaited<ReturnType<typeof createSession>> | undefined;
let pendingSession: ReturnType<typeof createSession> | undefined;

const instancePrincipalSigner = async () => {
	if (session && session.expiresAt - Date.now() > TOKEN_REFRESH_MARGIN_MS) {
		return session.signer;
	}
	pendingSession ??= createSession().finally(() => {
		pendingSession = undefined;
	});
	session = await pendingSession;
	return session.signer;
};

const signerFor = async (config: OciConfig): Promise<Signer> => {
	if (config.authType === "instancePrincipal") {
		if (IS_CLOUD) {
			throw new Error(
				"OCI Vault: instance principal authentication is not available on Dokploy Cloud",
			);
		}
		// Every organization on this server would act as the host's OCI identity,
		// so the server's administrator has to opt in.
		if (process.env[INSTANCE_PRINCIPAL_ENV] !== "true") {
			throw new Error(
				`OCI Vault: instance principal authentication is disabled on this server. Its administrator can enable it by setting ${INSTANCE_PRINCIPAL_ENV}=true`,
			);
		}
		return instancePrincipalSigner();
	}
	// Configs stored before authType existed have none, and are API keys.
	return {
		keyId: `${config.tenancyId}/${config.userId}/${config.fingerprint.toLowerCase()}`,
		key: loadSigningKey(config),
		principal: "the user",
		authFailureHint:
			"Check the tenancy, user, fingerprint and private key, and that the server clock is correct",
	};
};

export const ociClient: VaultClient<OciConfig> = {
	async getSecrets(config, refs) {
		const parsed = refs.map((ref) => ({ ref, ...parseRef(ref) }));
		const signer = await signerFor(config);

		const contents = new Map<string, string>();
		await Promise.all(
			[...new Set(parsed.map((entry) => entry.name))].map(async (name) => {
				contents.set(name, await readSecret(config, signer, name));
			}),
		);

		const result: Record<string, string> = {};
		for (const { ref, name, field } of parsed) {
			const content = contents.get(name) as string;
			if (field === null) {
				result[ref] = content;
				continue;
			}
			let json: Record<string, unknown>;
			try {
				json = JSON.parse(content);
			} catch {
				throw new Error(
					`OCI Vault: secret "${name}" is not JSON, cannot extract field "${field}"`,
				);
			}
			const value = json[field];
			if (value === undefined || value === null) {
				throw new Error(
					`OCI Vault: field "${field}" not found in secret "${name}"`,
				);
			}
			result[ref] = typeof value === "string" ? value : JSON.stringify(value);
		}
		return result;
	},

	async testConnection(config) {
		const signer = await signerFor(config);
		await request(signer, "GET", listUrl(config, 1), listNotFound(signer));
	},

	async listSecretNames(config) {
		const signer = await signerFor(config);
		const names: string[] = [];
		let page: string | undefined;
		do {
			const response = await request(
				signer,
				"GET",
				listUrl(config, PAGE_SIZE, page),
				listNotFound(signer),
			);
			const secrets = (await response.json()) as { secretName?: string }[];
			for (const secret of secrets) {
				if (secret.secretName) {
					names.push(secret.secretName);
				}
			}
			page = response.headers.get("opc-next-page") ?? undefined;
		} while (page && names.length < MAX_LISTED_SECRETS);
		return names.slice(0, MAX_LISTED_SECRETS);
	},
};
