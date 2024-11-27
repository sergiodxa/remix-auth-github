# GitHubStrategy

A Remix Auth's strategy for GitHub Apps and OAuth Apps

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## How to use

### Installation

```bash
npm add remix-auth remix-auth-github
```

### Create an OAuth application

Follow the steps on [the GitHub documentation](https://docs.github.com/en/developers/apps/building-oauth-apps/creating-an-oauth-app) to create a new application and get a client ID and secret.

### Usage

You can use this strategy by adding it to your authenticator instance and configuring the correct endpoints.

```ts
export let authenticator = new Authenticator<User>();

authenticator.use(
  new GitHubStrategy(
    {
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectURI: "https://example.app/auth/callback",
      scopes: ["user:email"], // optional
    },
    async ({ tokens, request }) => {
      // here you can use the params above to get the user and return it
      // what you do inside this and how you find the user is up to you
      return await getUser(tokens, request);
    }
  ),
  // this is optional, but if you setup more than one GitHub instance you will
  // need to set a custom name to each one, by default is "github"
  "provider-name"
);
```

Then you will need to setup your routes, for the OAuth2 flows you will need to call the `authenticate` method twice.

First, you will call the `authenticate` method with the provider name you set in the authenticator.

```ts
export async function action({ request }: Route.ActionArgs) {
  await authenticator.authenticate("provider-name", { request });
}
```

> [!NOTE]
> This route can be an `action` or a `loader`, it depends if you trigger the flow doing a POST or GET request.

This will start the OAuth2 flow and redirect the user to the provider's login page. Once the user logs in and authorizes your application, the provider will redirect the user back to your application redirect URI.

You will now need a route on that URI to handle the callback from the provider.

```ts
export async function loader({ request }: Route.LoaderArgs) {
  let user = await authenticator.authenticate("provider-name", { request });
  // now you have the user object with the data you returned in the verify function
}
```

> [!NOTE]
> This route must be a `loader` as the redirect will trigger a `GET` request.

Once you have the `user` object returned by your strategy verify function, you can do whatever you want with that information. This can be storing the user in a session, creating a new user in your database, link the account to an existing user in your database, etc.

### Using the Refresh Token

The strategy exposes a public `refreshToken` method that you can use to refresh the access token.

```ts
let strategy = new GitHubStrategy<User>(options, verify);
let tokens = await strategy.refreshToken(refreshToken);
```

The refresh token is part of the `tokens` object the verify function receives. How you store it to call `strategy.refreshToken` and what you do with the `tokens` object after it is up to you.

The most common approach would be to store the refresh token in the user data and then update the session after refreshing the token.

```ts
authenticator.use(
  new GitHubStrategy<User>(
    options,
    async ({ tokens, request }) => {
      let user = await getUser(tokens, request);
      return {
        ...user,
        accessToken: tokens.accessToken()
        refreshToken: tokens.hasRefreshToken() ? tokens.refreshToken() : null,
      }
    }
  )
);

// later in your code you can use it to get new tokens object
let tokens = await strategy.refreshToken(user.refreshToken);
```
