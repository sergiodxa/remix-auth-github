import { beforeEach, describe, expect, mock, test } from "bun:test";
import { createCookieSessionStorage } from "@remix-run/node";
import { AuthenticateOptions } from "remix-auth";
import { GitHubStrategy } from "../src";

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

	beforeEach(() => mock.restore());

	test("should allow changing the scope", async () => {
		let strategy = new GitHubStrategy(
			{
				clientId: "CLIENT_ID",
				clientSecret: "CLIENT_SECRET",
				redirectURI: "https://example.app/callback",
				scopes: ["user:email"],
			},
			verify,
		);

		let request = new Request("https://example.app/auth/github");

		try {
			await strategy.authenticate(request, sessionStorage, BASE_OPTIONS);
		} catch (error) {
			if (!(error instanceof Response)) throw error;
			let location = error.headers.get("Location");

			if (!location) throw new Error("No redirect header");

			let redirectUrl = new URL(location);

			expect(redirectUrl.searchParams.get("scope")).toBe("user:email");
		}
	});

	test("should allow typed scope array", async () => {
		let strategy = new GitHubStrategy(
			{
				clientId: "CLIENT_ID",
				clientSecret: "CLIENT_SECRET",
				redirectURI: "https://example.app/callback",
				scopes: ["read:user"],
			},
			verify,
		);

		let request = new Request("https://example.app/auth/github");

		try {
			await strategy.authenticate(request, sessionStorage, BASE_OPTIONS);
		} catch (error) {
			if (!(error instanceof Response)) throw error;
			let location = error.headers.get("Location");

			if (!location) throw new Error("No redirect header");

			let redirectUrl = new URL(location);

			expect(redirectUrl.searchParams.get("scope")).toBe("read:user");
		}
	});

	test("should have the scope `user:email` as default", async () => {
		let strategy = new GitHubStrategy(
			{
				clientId: "CLIENT_ID",
				clientSecret: "CLIENT_SECRET",
				redirectURI: "https://example.app/callback",
			},
			verify,
		);

		let request = new Request("https://example.app/auth/github");

		try {
			await strategy.authenticate(request, sessionStorage, BASE_OPTIONS);
		} catch (error) {
			if (!(error instanceof Response)) throw error;
			let location = error.headers.get("Location");

			if (!location) throw new Error("No redirect header");

			let redirectUrl = new URL(location);

			expect(redirectUrl.searchParams.get("scope")).toBe("user:email");
		}
	});

	test("should correctly format the authorization URL", async () => {
		let strategy = new GitHubStrategy(
			{
				clientId: "CLIENT_ID",
				clientSecret: "CLIENT_SECRET",
				redirectURI: "https://example.app/callback",
			},
			verify,
		);

		let request = new Request("https://example.app/auth/github");

		try {
			await strategy.authenticate(request, sessionStorage, BASE_OPTIONS);
		} catch (error) {
			if (!(error instanceof Response)) throw error;

			let location = error.headers.get("Location");

			if (!location) throw new Error("No redirect header");

			let redirectUrl = new URL(location);

			expect(redirectUrl.hostname).toBe("github.com");
			expect(redirectUrl.pathname).toBe("/login/oauth/authorize");
		}
	});
});
