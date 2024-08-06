import { Request } from "./request.js";

export namespace Emails {
	export type Type = Array<{
		email: string;
		verified: boolean;
		primary: boolean;
		visibility: string | null;
	}>;

	export class Response {
		constructor(public body: object) {}

		emails() {
			if (!Array.isArray(this.body)) return [];
			let isValid = this.body.every((item: unknown) => {
				if (typeof item !== "object") return false;
				if (item === null) return false;
				if (Array.isArray(item)) return false;
				return (
					"email" in item &&
					"verified" in item &&
					"primary" in item &&
					"visibility" in item
				);
			});
			if (!isValid) return [];
			let emails = this.body as Type;
			return (
				emails
					.filter(({ verified }) => verified) // Filter out unverified emails
					// Sort to keep the primary email first
					.sort((a, b) => {
						if (a.primary && !b.primary) return -1;
						if (!a.primary && b.primary) return 1;
						return 0;
					})
					.map(({ email, primary }) => ({
						value: email,
						type: primary ? "primary" : "secondary",
					}))
			);
		}
	}

	export async function send(
		endpoint: URL,
		context: Request.Context,
		options?: { signal?: AbortSignal },
	) {
		let request = context.toRequest(endpoint);
		let response = await fetch(request, { signal: options?.signal });
		let body = await response.json();

		let result = new Response(body);

		return result.emails();
	}
}
