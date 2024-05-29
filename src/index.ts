import type { StrategyVerifyCallback } from "remix-auth";
import { OAuth2Strategy } from "remix-auth-oauth2";
import type {
	OAuth2Profile,
	OAuth2StrategyOptions,
	OAuth2StrategyVerifyParams,
	TokenResponseBody,
} from "remix-auth-oauth2";

type URLConstructor = string | URL;

export type GitHubEmails = NonNullable<OAuth2Profile["emails"]>;

export type GitHubEmailsResponse = {
	email: string;
	verified: boolean;
	primary: boolean;
	visibility: string | null;
}[];

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
	| "admin:gpg_key"
	| "write:gpg_key"
	| "read:gpg_key"
	| "codespace"
	| "workflow"
	| "write:discussion"
	| "read:discussion";

export interface GitHubProfile extends OAuth2Profile {
	provider: "github";
	displayName: string;
	name: {
		familyName: string;
		givenName: string;
		middleName: string;
	};
	emails: GitHubEmails;
	photos: [{ value: string }];
	_json: {
		login: string;
		id: number;
		node_id: string;
		avatar_url: string;
		gravatar_id: string;
		url: string;
		html_url: string;
		followers_url: string;
		following_url: string;
		gists_url: string;
		starred_url: string;
		subscriptions_url: string;
		organizations_url: string;
		repos_url: string;
		events_url: string;
		received_events_url: string;
		type: string;
		site_admin: boolean;
		name: string;
		company: string;
		blog: string;
		location: string;
		email: string;
		hireable: boolean;
		bio: string;
		twitter_username: string;
		public_repos: number;
		public_gists: number;
		followers: number;
		following: number;
		created_at: string;
		updated_at: string;
		private_gists: number;
		total_private_repos: number;
		owned_private_repos: number;
		disk_usage: number;
		collaborators: number;
		two_factor_authentication: boolean;
		plan: {
			name: string;
			space: number;
			private_repos: number;
			collaborators: number;
		};
	};
}

export interface GitHubStrategyOptions
	extends Omit<
		OAuth2StrategyOptions,
		"authorizationEndpoint" | "tokenEndpoint"
	> {
	scopes?: GitHubScope[];
	allowSignup?: boolean;
	userAgent?: string;
	userInfoEndpoint?: URLConstructor;
	userEmailsEndpoint?: URLConstructor;
	/**
	 * The endpoint the Identity Provider asks you to send users to log in, or
	 * authorize your application.
	 */
	authorizationEndpoint?: URLConstructor;
	/**
	 * The endpoint the Identity Provider uses to let's you exchange an access
	 * code for an access and refresh token.
	 */
	tokenEndpoint?: URLConstructor;
}

export interface GitHubStrategyVerifyParams
	extends OAuth2StrategyVerifyParams<GitHubProfile> {}

export const UserInfoURL = "https://api.github.com/user";
export const UserEmailsURL = "https://api.github.com/user/emails";
export const AuthorizationURL = new URL(
	"https://github.com/login/oauth/authorize",
);
export const TokenURL = new URL("https://github.com/login/oauth/access_token");

export class GitHubStrategy<User> extends OAuth2Strategy<User, GitHubProfile> {
	name = "github";

	protected allowSignup: boolean;
	protected userAgent: string;
	protected userEmailsEndpoint: URLConstructor;
	protected userInfoEndpoint: URLConstructor;

	constructor(
		{
			allowSignup,
			userAgent,
			userEmailsEndpoint,
			userInfoEndpoint,
			...options
		}: GitHubStrategyOptions,
		verify: StrategyVerifyCallback<User, GitHubStrategyVerifyParams>,
	) {
		super(
			{
				authorizationEndpoint: AuthorizationURL,
				tokenEndpoint: TokenURL,
				...options,
			},
			verify,
		);

		this.allowSignup = allowSignup ?? false;
		this.userAgent = userAgent ?? "Remix Auth's GitHubStrategy";
		this.userInfoEndpoint = userInfoEndpoint ?? UserInfoURL;
		this.userEmailsEndpoint = userEmailsEndpoint ?? UserEmailsURL;
	}

	protected authorizationParams(params: URLSearchParams): URLSearchParams {
		if (this.allowSignup) params.set("allow_signup", "true");
		return params;
	}

	protected async userProfile(
		tokens: TokenResponseBody,
	): Promise<GitHubProfile> {
		let response = await fetch(this.userInfoEndpoint, {
			headers: {
				Accept: "application/vnd.github.v3+json",
				Authorization: `token ${tokens.access_token}`,
				"User-Agent": this.userAgent,
			},
		});

		let data = (await response.json()) as GitHubProfile["_json"];

		let emails: GitHubProfile["emails"] = [];

		if (
			this.options.scopes?.includes("user") ||
			this.options.scopes?.includes("user:email")
		) {
			emails.concat(await this.fetchUserEmails(tokens));
		} else emails.push({ value: data.email });

		return {
			provider: "github",
			displayName: data.login,
			id: data.id.toString(),
			name: {
				familyName: data.name,
				givenName: data.name,
				middleName: data.name,
			},
			emails: emails,
			photos: [{ value: data.avatar_url }],
			_json: data,
		} satisfies GitHubProfile;
	}

	protected async fetchUserEmails(
		tokens: TokenResponseBody,
	): Promise<GitHubEmails> {
		let response = await fetch(this.userEmailsEndpoint, {
			headers: {
				Accept: "application/vnd.github.v3+json",
				Authorization: `token ${tokens.access_token}`,
				"User-Agent": this.userAgent,
			},
		});

		let data = (await response.json()) as GitHubEmailsResponse;

		let emails: GitHubEmails = data
			.filter(({ verified }) => verified) // Filter out unverified emails
			// Sort to keep the primary email first
			.sort((a, b) => {
				if (a.primary && !b.primary) return -1;
				if (!a.primary && b.primary) return 1;
				return 0;
			})
			.map(({ email }) => ({ value: email }));

		return emails;
	}
}
