import type { StrategyVerifyCallback } from "remix-auth";
import { AuthorizationError } from "remix-auth";
import {
  OAuth2Profile,
  OAuth2Strategy,
  OAuth2StrategyVerifyParams,
} from "remix-auth-oauth2";

export interface GitHubStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: GitHubScope[] | string;
  allowSignup?: boolean;
  userAgent?: string;
  authorizationURL?: string;
  tokenURL?: string;
  userInfoURL?: string;
  userEmailsURL?: string;
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
  | "delete_repo"
  | "write:discussion"
  | "read:discussion"
  | "write:packages"
  | "read:packages"
  | "delete:packages"
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

export interface GitHubExtraParams
  extends Record<string, string | number | null> {
  tokenType: string;
  accessTokenExpiresIn: number | null;
  refreshTokenExpiresIn: number | null;
}

export const GitHubStrategyDefaultName = "github";
export const GitHubStrategyDefaultScope: GitHubScope = "user:email";
export const GitHubStrategyScopeSeperator = " ";

export class GitHubStrategy<User> extends OAuth2Strategy<
  User,
  GitHubProfile,
  GitHubExtraParams
> {
  name = GitHubStrategyDefaultName;

  scope: string;
  private allowSignup: boolean;
  private userAgent: string;
  private userInfoURL: string;
  private userEmailsURL: string;

  constructor(
    {
      clientID,
      clientSecret,
      callbackURL,
      scope,
      allowSignup,
      userAgent,
      userInfoURL = "https://api.github.com/user",
      userEmailsURL = "https://api.github.com/user/emails",
      authorizationURL = "https://github.com/login/oauth/authorize",
      tokenURL = "https://github.com/login/oauth/access_token",
    }: GitHubStrategyOptions,
    verify: StrategyVerifyCallback<
      User,
      OAuth2StrategyVerifyParams<GitHubProfile, GitHubExtraParams>
    >,
  ) {
    super(
      {
        clientID,
        clientSecret,
        callbackURL,
        authorizationURL,
        tokenURL,
      },
      verify,
    );
    this.scope = this.getScope(scope).join(GitHubStrategyScopeSeperator);
    this.allowSignup = allowSignup ?? true;
    this.userAgent = userAgent ?? "Remix Auth";
    this.userInfoURL = userInfoURL;
    this.userEmailsURL = userEmailsURL;
  }

  //Allow users the option to pass a scope string, or typed array
  private getScope(scope: GitHubStrategyOptions["scope"]) {
    if (!scope) {
      return [GitHubStrategyDefaultScope];
    } else if (typeof scope === "string") {
      return scope.split(GitHubStrategyScopeSeperator) as GitHubScope[];
    }

    return scope;
  }

  protected authorizationParams() {
    return new URLSearchParams({
      scope: this.scope,
      allow_signup: String(this.allowSignup),
    });
  }

  protected async userEmails(accessToken: string): Promise<GitHubEmails> {
    let response = await fetch(this.userEmailsURL, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: `token ${accessToken}`,
        "User-Agent": this.userAgent,
      },
    });

    let data: GitHubEmailsResponse = await response.json();

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

  protected async userProfile(accessToken: string): Promise<GitHubProfile> {
    let response = await fetch(this.userInfoURL, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        Authorization: `token ${accessToken}`,
        "User-Agent": this.userAgent,
      },
    });

    let data: GitHubProfile["_json"] = await response.json();

    let emails: GitHubProfile["emails"] = [{ value: data.email }];

    if (this.scope.includes(GitHubStrategyDefaultScope)) {
      emails = await this.userEmails(accessToken);
    }

    let profile: GitHubProfile = {
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
    };

    return profile;
  }

  protected async getAccessToken(response: Response): Promise<{
    accessToken: string;
    refreshToken: string;
    extraParams: GitHubExtraParams;
  }> {
    let data = new URLSearchParams(await response.text());

    let accessToken = data.get("access_token");
    if (!accessToken) throw new AuthorizationError("Missing access token.");

    let tokenType = data.get("token_type");
    if (!tokenType) throw new AuthorizationError("Missing token type.");

    let refreshToken = data.get("refresh_token") ?? "";
    let accessTokenExpiresIn = parseExpiresIn(data.get("expires_in"));
    let refreshTokenExpiresIn = parseExpiresIn(
      data.get("refresh_token_expires_in"),
    );

    return {
      accessToken,
      refreshToken,
      extraParams: {
        tokenType,
        accessTokenExpiresIn,
        refreshTokenExpiresIn,
      },
    } as const;
  }
}

function parseExpiresIn(value: string | null): number | null {
  if (!value) return null;

  try {
    return Number.parseInt(value, 10);
  } catch {
    return null;
  }
}
