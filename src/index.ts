import { Cookie, SetCookie, type SetCookieInit } from "@mjackson/headers";
import {
	GitHub,
	OAuth2RequestError,
	OAuth2Tokens,
	generateState,
} from "arctic";
import createDebug from "debug";
import { Strategy } from "remix-auth/strategy";
import { redirect } from "./lib/redirect.js";

type URLConstructor = ConstructorParameters<typeof URL>[0];

const debug = createDebug("GitHubStrategy");

export class GitHubStrategy<User> extends Strategy<
	User,
	GitHubStrategy.VerifyOptions
> {
	name = "github";

	protected client: GitHub;

	constructor(
		protected options: GitHubStrategy.ConstructorOptions,
		verify: Strategy.VerifyFunction<User, GitHubStrategy.VerifyOptions>,
	) {
		super(verify);

		this.client = new GitHub(
			options.clientId,
			options.clientSecret,
			options.redirectURI.toString(),
		);
	}

	private get cookieName() {
		if (typeof this.options.cookie === "string") {
			return this.options.cookie || "github";
		}
		return this.options.cookie?.name ?? "github";
	}

	private get cookieOptions() {
		if (typeof this.options.cookie !== "object") return {};
		return this.options.cookie ?? {};
	}

	override async authenticate(request: Request): Promise<User> {
		debug("Request URL", request.url);

		let url = new URL(request.url);

		let stateUrl = url.searchParams.get("state");
		let error = url.searchParams.get("error");

		if (error) {
			let description = url.searchParams.get("error_description");
			let uri = url.searchParams.get("error_uri");
			throw new OAuth2RequestError(error, description, uri, stateUrl);
		}

		if (!stateUrl) {
			debug("No state found in the URL, redirecting to authorization endpoint");

			let state = generateState();

			let url = this.client.createAuthorizationURL(
				state,
				this.options.scopes ?? [],
			);

			debug("State", state);

			url.search = this.authorizationParams(
				url.searchParams,
				request,
			).toString();

			debug("Authorization URL", url.toString());

			let header = new SetCookie({
				name: this.cookieName,
				value: new URLSearchParams({ state }).toString(),
				httpOnly: true, // Prevents JavaScript from accessing the cookie
				maxAge: 60 * 5, // 5 minutes
				path: "/", // Allow the cookie to be sent to any path
				sameSite: "Lax", // Prevents it from being sent in cross-site requests
				...this.cookieOptions,
			});

			throw redirect(url.toString(), {
				headers: { "Set-Cookie": header.toString() },
			});
		}

		let code = url.searchParams.get("code");

		if (!code) throw new ReferenceError("Missing code in the URL");

		let cookie = new Cookie(request.headers.get("cookie") ?? "");
		let params = new URLSearchParams(cookie.get(this.cookieName));

		if (!params.has("state")) {
			throw new ReferenceError("Missing state on cookie.");
		}

		if (params.get("state") !== stateUrl) {
			throw new RangeError("State in URL doesn't match state in cookie.");
		}

		debug("Validating authorization code");
		let tokens = await this.client.validateAuthorizationCode(code);

		debug("Verifying the user profile");
		let user = await this.verify({ request, tokens });

		debug("User authenticated");
		return user;
	}

	protected createAuthorizationURL() {
		let state = generateState();

		let url = this.client.createAuthorizationURL(
			state,
			this.options.scopes ?? [],
		);

		return { state, url };
	}

	/**
	 * Return extra parameters to be included in the authorization request.
	 *
	 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
	 * included when requesting authorization.  Since these parameters are not
	 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
	 * strategies can override this function in order to populate these
	 * parameters as required by the provider.
	 */
	protected authorizationParams(
		params: URLSearchParams,
		request: Request,
	): URLSearchParams {
		return new URLSearchParams(params);
	}

	/**
	 * Get a new OAuth2 Tokens object using the refresh token once the previous
	 * access token has expired.
	 * @param refreshToken The refresh token to use to get a new access token
	 * @returns The new OAuth2 tokens object
	 * @example
	 * ```ts
	 * let tokens = await strategy.refreshToken(refreshToken);
	 * console.log(tokens.accessToken());
	 * ```
	 */
	public refreshToken(refreshToken: string) {
		return this.client.refreshAccessToken(refreshToken);
	}
}

export namespace GitHubStrategy {
	export interface VerifyOptions {
		/** The request that triggered the verification flow */
		request: Request;
		/** The OAuth2 tokens retrivied from the identity provider */
		tokens: OAuth2Tokens;
	}

	export interface ConstructorOptions {
		/**
		 * The name of the cookie used to keep state and code verifier around.
		 *
		 * The OAuth2 flow requires generating a random state and code verifier, and
		 * then checking that the state matches when the user is redirected back to
		 * the application. This is done to prevent CSRF attacks.
		 *
		 * The state and code verifier are stored in a cookie, and this option
		 * allows you to customize the name of that cookie if needed.
		 * @default "github"
		 */
		cookie?: string | (Omit<SetCookieInit, "value"> & { name: string });

		/**
		 * This is the Client ID of your application, provided to you by the Identity
		 * Provider you're using to authenticate users.
		 */
		clientId: string;
		/**
		 * This is the Client Secret of your application, provided to you by the
		 * Identity Provider you're using to authenticate users.
		 */
		clientSecret: string;

		/**
		 * The URL of your application where the Identity Provider will redirect the
		 * user after they've logged in or authorized your application.
		 */
		redirectURI: URLConstructor;

		/**
		 * The scopes you want to request from the Identity Provider, this is a list
		 * of strings that represent the permissions you want to request from the
		 * user.
		 */
		scopes?: Scope[];
	}

	/**
	 * @see https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps#available-scopes
	 */
	export type Scope =
		| "repo"
		| "repo:status"
		| "repo_deployment"
		| "public_repo"
		| "repo:invite"
		| "security_events"
		| "admin:repo_hook"
		| "write:repo_hook"
		| "read:repo_hook"
		| "admin:org"
		| "write:org"
		| "read:org"
		| "admin:public_key"
		| "write:public_key"
		| "read:public_key"
		| "admin:org_hook"
		| "gist"
		| "notifications"
		| "user"
		| "read:user"
		| "user:email"
		| "user:follow"
		| "project"
		| "read:project"
		| "delete_repo"
		| "write:packages"
		| "read:packages"
		| "delete:packages"
		| "write:discussion"
		| "read:discussion"
		| "admin:gpg_key"
		| "write:gpg_key"
		| "read:gpg_key"
		| "codespace"
		| "workflow";
}
