import type { StrategyVerifyCallback } from "remix-auth";
import {
	type OAuth2Profile,
	OAuth2Strategy,
	type OAuth2StrategyOptions,
	type OAuth2StrategyVerifyParams,
	type TokenResponseBody,
} from "remix-auth-oauth2";
import { Emails } from "./lib/emails.js";
import { Request } from "./lib/request.js";
import { UserProfile } from "./lib/user-profile.js";

type URLConstructor = ConstructorParameters<typeof URL>[0];

export interface GitHubStrategyOptions
	extends Omit<
		OAuth2StrategyOptions,
		"scopes" | "authorizationEndpoint" | "tokenEndpoint"
	> {
	scopes?: GitHubScope[];
	allowSignup?: boolean;
	userAgent?: string;
	authorizationEndpoint?: URLConstructor;
	tokenEndpoint?: URLConstructor;
	userInfoEndpoint?: URLConstructor;
	userEmailsEndpoint?: URLConstructor;
}

/**
 * @see https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps#available-scopes
 */
export type GitHubScope =
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

export type GitHubEmails = NonNullable<OAuth2Profile["emails"]>;
export type GitHubEmailsResponse = {
	email: string;
	verified: boolean;
	primary: boolean;
	visibility: string | null;
}[];

export interface GitHubProfile extends OAuth2Profile {
	id: string;
	displayName: string;
	name: {
		familyName: string;
		givenName: string;
		middleName: string;
	};
	emails: NonNullable<OAuth2Profile["emails"]>;
	photos: NonNullable<OAuth2Profile["photos"]>;
	_json: UserProfile.Type;
}

export interface GitHubExtraParams
	extends Record<string, string | number | null> {
	tokenType: string;
	accessTokenExpiresIn: number | null;
	refreshTokenExpiresIn: number | null;
}

export let GitHubStrategyDefaultName = "github";
export let GitHubStrategyDefaultScope: GitHubScope = "user:email";
export let GitHubStrategyScopeSeperator = " ";

export class GitHubStrategy<User> extends OAuth2Strategy<
	User,
	GitHubProfile,
	GitHubExtraParams
> {
	override name = GitHubStrategyDefaultName;

	private allowSignup: boolean;
	private userAgent: string;
	private userInfoEndpoint: URL;
	private userEmailsEndpoint: URL;

	constructor(
		{
			allowSignup,
			userAgent,
			scopes = [GitHubStrategyDefaultScope],
			userInfoEndpoint = "https://api.github.com/user",
			userEmailsEndpoint = "https://api.github.com/user/emails",
			authorizationEndpoint = "https://github.com/login/oauth/authorize",
			tokenEndpoint = "https://github.com/login/oauth/access_token",
			...options
		}: GitHubStrategyOptions,
		verify: StrategyVerifyCallback<
			User,
			OAuth2StrategyVerifyParams<GitHubProfile, GitHubExtraParams>
		>,
	) {
		super(
			{
				...options,
				scopes,
				authorizationEndpoint,
				tokenEndpoint,
			},
			verify,
		);
		this.allowSignup = allowSignup ?? true;
		this.userAgent = userAgent ?? "Remix Auth";
		this.userInfoEndpoint = new URL(userInfoEndpoint);
		this.userEmailsEndpoint = new URL(userEmailsEndpoint);
	}

	protected override authorizationParams(
		params: URLSearchParams,
	): URLSearchParams {
		let searchParams = new URLSearchParams(params);
		if (this.allowSignup) searchParams.set("allow_signup", "true");
		return searchParams;
	}

	protected async userEmails(accessToken: string): Promise<GitHubEmails> {
		let context = new Request.Context("GET", this.userAgent);
		context.authorize(accessToken);
		return await Emails.send(this.userEmailsEndpoint, context);
	}

	protected override async userProfile(
		tokens: TokenResponseBody,
	): Promise<GitHubProfile> {
		let context = new Request.Context("GET", this.userAgent);
		context.authorize(tokens.access_token);

		let profile = await UserProfile.send(this.userInfoEndpoint, context);
		let emails: GitHubProfile["emails"] = [{ value: profile.email }];

		if (this.options.scopes?.includes(GitHubStrategyDefaultScope)) {
			emails = await this.userEmails(tokens.access_token);
		}

		return {
			provider: "github",
			displayName: profile.login,
			id: profile.id.toString(),
			name: {
				familyName: profile.name,
				givenName: profile.name,
				middleName: profile.name,
			},
			emails: emails,
			photos: [{ value: profile.avatar_url }],
			_json: profile,
		} satisfies GitHubProfile;
	}
}
