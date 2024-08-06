type URLConstructor = ConstructorParameters<typeof URL>[0];

export namespace Request {
	export class Context {
		public method: string;
		public body = new Map<string, string>();
		public headers = new Headers();

		constructor(method: string, userAgent: string) {
			this.method = method;
			this.headers.set("Content-Type", "application/json");
			this.headers.set("Accept", "application/vnd.github.v3+json");
			this.headers.set("User-Agent", userAgent);
		}

		authorize(token: string) {
			this.headers.set("Authorization", `token ${token}`);
		}

		toRequest(url: URLConstructor) {
			let init: RequestInit = { method: this.method, headers: this.headers };
			if (init.method !== "GET" && init.method !== "HEAD") {
				init.body = JSON.stringify(Object.fromEntries(this.body));
			}
			return new globalThis.Request(url, init);
		}
	}
}
