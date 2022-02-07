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
  scope?: string;
  allowSignup?: boolean;
  userAgent?: string;
}

export type GitHubEmails = OAuth2Profile["emails"];
export type GitHubEmailsResponse = { email: string }[];

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

export interface GitHubExtraParams extends Record<string, string | number> {
  tokenType: string;
}

export class GitHubStrategy<User> extends OAuth2Strategy<
  User,
  GitHubProfile,
  GitHubExtraParams
> {
  name = "github";

  private USER_EMAIL_SCOPE = "user:email";
  private scope: string;
  private allowSignup: boolean;
  private userAgent: string;
  private userInfoURL = "https://api.github.com/user";
  private userEmailsURL = "https://api.github.com/user/emails";

  constructor(
    {
      clientID,
      clientSecret,
      callbackURL,
      scope,
      allowSignup,
      userAgent,
    }: GitHubStrategyOptions,
    verify: StrategyVerifyCallback<
      User,
      OAuth2StrategyVerifyParams<GitHubProfile, GitHubExtraParams>
    >
  ) {
    super(
      {
        clientID,
        clientSecret,
        callbackURL,
        authorizationURL: "https://github.com/login/oauth/authorize",
        tokenURL: "https://github.com/login/oauth/access_token",
      },
      verify
    );
    this.scope = scope ?? this.USER_EMAIL_SCOPE;
    this.allowSignup = allowSignup ?? true;
    this.userAgent = userAgent ?? "Remix Auth";
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
    let emails: GitHubEmails = data.map(({ email }) => ({ value: email }));
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

    let emails: GitHubProfile["emails"] = [
      {
        value: data.email,
      },
    ];

    if (this.scope.includes(this.USER_EMAIL_SCOPE)) {
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
    let data = await response.text();

    let accessToken = new URLSearchParams(data).get("access_token");
    if (!accessToken) throw new AuthorizationError("Missing access token.");

    let tokenType = new URLSearchParams(data).get("token_type");
    if (!tokenType) throw new AuthorizationError("Missing token type.");

    return {
      accessToken,
      refreshToken: "",
      extraParams: { tokenType },
    } as const;
  }
}
