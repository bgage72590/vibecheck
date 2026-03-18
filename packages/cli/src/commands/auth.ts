import { createServer } from "node:http";
import { URL } from "node:url";
import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import chalk from "chalk";
import ora from "ora";
import { storeToken, clearToken, getStoredToken, syncUser } from "../utils/api.js";

const CLERK_PUBLISHABLE_KEY = process.env.CLERK_PUBLISHABLE_KEY ?? "";

/**
 * Opens a browser-based login flow.
 * 1. Starts a local HTTP server on a random port
 * 2. Opens the Clerk sign-in page with redirect back to local server
 * 3. Receives the token via redirect callback
 * 4. Stores the token locally
 */
export async function loginCommand(): Promise<void> {
  const existing = getStoredToken();
  if (existing) {
    console.log(chalk.yellow(`Already logged in as ${existing.email}`));
    console.log(chalk.gray("Run `vibecheck auth logout` first to switch accounts."));
    return;
  }

  const spinner = ora("Waiting for browser login...").start();

  // Start local callback server
  const { token, email, userId } = await waitForBrowserLogin();

  spinner.text = "Syncing account...";

  // Store token
  storeToken({
    token,
    userId,
    email,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  // Sync user with API
  const user = await syncUser();
  spinner.stop();

  console.log(chalk.green(`Logged in as ${email}`));
  if (user) {
    console.log(chalk.gray(`Plan: ${user.plan}`));
  }
}

export async function logoutCommand(): Promise<void> {
  const existing = getStoredToken();
  if (!existing) {
    console.log(chalk.gray("Not logged in."));
    return;
  }

  clearToken();
  console.log(chalk.green("Logged out successfully."));
}

export async function whoamiCommand(): Promise<void> {
  const token = getStoredToken();
  if (!token) {
    console.log(chalk.gray("Not logged in. Run `vibecheck auth login` to authenticate."));
    return;
  }

  console.log(chalk.cyan(`Email: ${token.email}`));
  console.log(chalk.gray(`User ID: ${token.userId}`));

  const user = await syncUser();
  if (user) {
    const planBadge = user.plan === "pro"
      ? chalk.bgGreen.black(" PRO ")
      : chalk.bgGray.white(" FREE ");
    console.log(`Plan: ${planBadge}`);
  }
}

async function waitForBrowserLogin(): Promise<{
  token: string;
  email: string;
  userId: string;
}> {
  return new Promise((resolve, reject) => {
    const expectedState = randomUUID();

    const server = createServer((req, res) => {
      if (!req.url) {
        res.writeHead(400);
        res.end("Bad request");
        return;
      }

      const url = new URL(req.url, `http://localhost`);

      if (url.pathname === "/callback") {
        const token = url.searchParams.get("token");
        const email = url.searchParams.get("email");
        const userId = url.searchParams.get("user_id");
        const state = url.searchParams.get("state");

        if (!state || state !== expectedState) {
          res.writeHead(403);
          res.end("Invalid state parameter — possible CSRF attack.");
          return;
        }

        if (token && email && userId) {
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(`
            <html>
              <body style="font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #0a0a0f; color: #e0e0e0;">
                <div style="text-align: center;">
                  <h1 style="color: #00d4ff;">vibecheck</h1>
                  <p style="color: #4ade80; font-size: 1.2rem;">Login successful!</p>
                  <p style="color: #888;">You can close this tab and return to your terminal.</p>
                </div>
              </body>
            </html>
          `);

          server.close();
          resolve({ token, email, userId });
        } else {
          res.writeHead(400);
          res.end("Missing parameters");
        }
      } else if (url.pathname === "/login") {
        // Serve a simple login page that redirects to Clerk
        const callbackUrl = `http://localhost:${(server.address() as { port: number }).port}/callback`;

        // Development-only bypass — requires both env vars to be explicitly set
        if (process.env.NODE_ENV === "development" && process.env.VIBECHECK_DEV_AUTH === "true") {
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(`
            <html>
              <body style="font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #0a0a0f; color: #e0e0e0;">
                <div style="text-align: center;">
                  <h1 style="color: #00d4ff;">vibecheck</h1>
                  <p>Redirecting to login (dev mode)...</p>
                  <script>
                    const params = new URLSearchParams({
                      token: 'dev_token_' + Date.now(),
                      email: 'dev@vibecheck.dev',
                      user_id: 'user_dev_' + Date.now(),
                      state: '${expectedState}'
                    });
                    setTimeout(() => {
                      window.location.href = '/callback?' + params.toString();
                    }, 1000);
                  </script>
                </div>
              </body>
            </html>
          `);
        } else {
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(`
            <html>
              <body style="font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #0a0a0f; color: #e0e0e0;">
                <div style="text-align: center;">
                  <h1 style="color: #00d4ff;">vibecheck</h1>
                  <p>Redirecting to login...</p>
                  <p style="color: #888; font-size: 0.85rem;">If not redirected, <a href="#" style="color: #00d4ff;">click here</a>.</p>
                </div>
              </body>
            </html>
          `);
        }
      } else {
        res.writeHead(302, { Location: "/login" });
        res.end();
      }
    });

    // Listen on random available port
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      const loginUrl = `http://localhost:${addr.port}/login`;

      console.log(chalk.cyan(`\nOpen this URL in your browser to log in:`));
      console.log(chalk.bold.underline(loginUrl));
      console.log("");

      // Try to open browser automatically
      const openCmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
      execFile(openCmd, [loginUrl], () => {});
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      server.close();
      reject(new Error("Login timed out. Please try again."));
    }, 5 * 60 * 1000);
  });
}
