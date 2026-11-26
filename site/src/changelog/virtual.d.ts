// The changelog's releases, newest first, read from the repo's changelog/ folder at build time (scripts/changelog.ts).
declare module "virtual:changelog" {
  export const entries: import("./feed").Entry[]
}
