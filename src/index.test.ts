import { beforeEach, describe, expect, mock, test } from "bun:test";
import { createCookieSessionStorage } from "@remix-run/node";
import { AuthenticateOptions } from "remix-auth";
import { GitHubStrategy, GitHubStrategyOptions } from ".";

const BASE_OPTIONS: AuthenticateOptions = {
	name: "form",
	sessionKey: "user",
	sessionErrorKey: "error",
	sessionStrategyKey: "strategy",
};

describe(GitHubStrategy.name, () => {
	let verify = mock();
	let sessionStorage = createCookieSessionStorage({
		cookie: { secrets: ["s3cr3t"] },
	});

	let options = Object.freeze({
		clientId: "MY_CLIENT_ID",
		clientSecret: "MY_CLIENT_SECRET",
		redirectURI: "https://example.app/callback",
		scopes: ["user:email", "read:user"],
	} satisfies GitHubStrategyOptions);

	test("should allow changing the scope", async () => {
		let strategy = new GitHubStrategy(options, verify);

		let request = new Request("https://example.app/auth/github");

		let response = await strategy
			.authenticate(request, sessionStorage, BASE_OPTIONS)
			.then(() => {
				throw new Error("Should have failed.");
			})
			.catch((error: unknown) => {
				if (error instanceof Response) return error;
				throw error;
			});

		let location = response.headers.get("Location");

		if (!location) throw new Error("No redirect header");

		let redirectUrl = new URL(location);

		expect(redirectUrl.searchParams.get("scope")).toBe("user:email read:user");
	});

	test("should allow typed scope array", async () => {
		let strategy = new GitHubStrategy(
			{ ...options, scopes: ["read:user"] },
			verify,
		);

		let request = new Request("https://example.app/auth/github");

		let response = await strategy
			.authenticate(request, sessionStorage, BASE_OPTIONS)
			.then(() => {
				throw new Error("Should have failed.");
			})
			.catch((error: unknown) => {
				if (error instanceof Response) return error;
				throw error;
			});

		let location = response.headers.get("Location");

		if (!location) throw new Error("No redirect header");

		let redirectUrl = new URL(location);

		expect(redirectUrl.searchParams.get("scope")).toBe("read:user");
	});

	test("should not have a default scope", async () => {
		let strategy = new GitHubStrategy(
			{ ...options, scopes: undefined },
			verify,
		);

		let request = new Request("https://example.app/auth/github");

		let response = await strategy
			.authenticate(request, sessionStorage, BASE_OPTIONS)
			.then(() => {
				throw new Error("Should have failed.");
			})
			.catch((error: unknown) => {
				if (error instanceof Response) return error;
				throw error;
			});

		let location = response.headers.get("Location");

		if (!location) throw new Error("No redirect header");

		let redirectUrl = new URL(location);

		expect(redirectUrl.searchParams.get("scope")).toBe(null);
	});

	test("should correctly format the authorization URL", async () => {
		let strategy = new GitHubStrategy(options, verify);

		let request = new Request("https://example.app/auth/github");

		let response = await strategy
			.authenticate(request, sessionStorage, BASE_OPTIONS)
			.then(() => {
				throw new Error("Should have failed.");
			})
			.catch((error: unknown) => {
				if (error instanceof Response) return error;
				throw error;
			});

		let location = response.headers.get("Location");

		if (!location) throw new Error("No redirect header");

		let redirectUrl = new URL(location);

		expect(redirectUrl.hostname).toBe("github.com");
		expect(redirectUrl.pathname).toBe("/login/oauth/authorize");
	});
});
