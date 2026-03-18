# VibeCheck — Deployment & Setup Guide

## 1. Prerequisites

- Node.js 20+
- pnpm (`npm install -g pnpm`)
- Accounts: [Turso](https://turso.tech), [Clerk](https://clerk.com), [Stripe](https://stripe.com), [Vercel](https://vercel.com)

## 2. Turso Database

```bash
# Install Turso CLI
brew install tursodatabase/tap/turso

# Login & create database
turso auth login
turso db create vibecheck
turso db show vibecheck --url    # Copy the URL
turso db tokens create vibecheck  # Copy the token
```

Add to `.env`:
```
TURSO_DATABASE_URL=libsql://vibecheck-yourorg.turso.io
TURSO_AUTH_TOKEN=your-token
```

## 3. Clerk Authentication

1. Go to [clerk.com](https://clerk.com) and create a new application
2. Choose "Email" as sign-in method
3. Go to **API Keys** in the Clerk dashboard
4. Copy the keys to `.env`:

```
CLERK_SECRET_KEY=sk_test_...
CLERK_PUBLISHABLE_KEY=pk_test_...
```

5. In Clerk dashboard, go to **JWT Templates** > Create template:
   - Name: `vibecheck`
   - Claims: `{ "email": "{{user.primary_email_address}}" }`

## 4. Stripe Billing

### Create Product & Price

1. Go to [Stripe Dashboard](https://dashboard.stripe.com) > Products
2. Create product:
   - Name: **VibeCheck Pro**
   - Description: Unlimited security scans, scan history, CI integration
3. Add price:
   - $29/month, recurring
   - Copy the `price_...` ID

### Create Webhook

1. Go to Developers > Webhooks
2. Add endpoint: `https://api.vibecheck.dev/api/webhooks/stripe`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
4. Copy the webhook signing secret

Add to `.env`:
```
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRO_PRICE_ID=price_...
```

## 5. Deploy API to Vercel

```bash
cd packages/api
pnpm build

# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod

# Set environment variables
vercel env add TURSO_DATABASE_URL
vercel env add TURSO_AUTH_TOKEN
vercel env add CLERK_SECRET_KEY
vercel env add STRIPE_SECRET_KEY
vercel env add STRIPE_WEBHOOK_SECRET
vercel env add STRIPE_PRO_PRICE_ID
vercel env add APP_URL  # https://vibecheck.dev
```

Custom domain: `api.vibecheck.dev`

## 6. Deploy Dashboard to Vercel

```bash
cd packages/web

# Deploy
vercel --prod

# Set environment variables
vercel env add NEXT_PUBLIC_API_URL  # https://api.vibecheck.dev
vercel env add NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
vercel env add CLERK_SECRET_KEY
```

Custom domain: `vibecheck.dev`

## 7. Publish CLI to npm

```bash
cd packages/cli
pnpm build

# Login to npm
npm login

# Publish
npm publish
```

Users can then run:
```bash
npx vibecheck scan .
```

## 8. Update CLI API URL

Before publishing, update the default API URL in `packages/cli/src/utils/api.ts`:

```typescript
const API_BASE = process.env.VIBECHECK_API_URL ?? "https://api.vibecheck.dev";
```

## 9. Test End-to-End

```bash
# 1. Test CLI scan (no auth)
npx vibecheck scan test-app --no-ai

# 2. Test CLI login
vibecheck auth login

# 3. Test authenticated scan
vibecheck scan test-app

# 4. Test usage limits (run 4 scans)
vibecheck scan test-app --no-ai  # Should hit limit on 4th

# 5. Test upgrade flow
vibecheck upgrade  # Should open Stripe Checkout

# 6. Test webhook (use Stripe CLI)
stripe listen --forward-to localhost:3456/api/webhooks/stripe
stripe trigger checkout.session.completed
```

## 10. Custom Domain Setup (vibecheck.dev)

### Buy the domain
Register `vibecheck.dev` on [Namecheap](https://namecheap.com), [Cloudflare](https://cloudflare.com), or your preferred registrar.

### Point DNS to Vercel

Add these DNS records at your registrar:

**For the dashboard (vibecheck.dev):**
```
Type: A
Name: @
Value: 76.76.21.21

Type: CNAME
Name: www
Value: cname.vercel-dns.com
```

**For the API (api.vibecheck.dev):**
```
Type: CNAME
Name: api
Value: cname.vercel-dns.com
```

### Add domains in Vercel

```bash
# Dashboard project
cd packages/web
vercel domains add vibecheck.dev
vercel domains add www.vibecheck.dev

# API project
cd packages/api
vercel domains add api.vibecheck.dev
```

Vercel auto-provisions SSL certificates. Allow 5-10 minutes for DNS propagation.

### Update environment variables

After domains are live, update these env vars in Vercel:

- **API project:** `APP_URL=https://vibecheck.dev`
- **Dashboard project:** `NEXT_PUBLIC_API_URL=https://api.vibecheck.dev`
- **Stripe webhook:** Update endpoint URL to `https://api.vibecheck.dev/api/webhooks/stripe`
- **Clerk:** Add `https://vibecheck.dev` to allowed redirect URLs

### Verify

```bash
curl https://api.vibecheck.dev/
# Should return: {"name":"vibecheck-api","version":"0.1.0","status":"ok"}

curl https://vibecheck.dev/landing
# Should return the landing page HTML
```

## 11. Product Hunt Launch Checklist

- [ ] npm package published and `npx vibecheck scan .` works
- [ ] API deployed and healthy at api.vibecheck.dev
- [ ] Dashboard live at vibecheck.dev
- [ ] Stripe checkout flow tested end-to-end
- [ ] GitHub Action tested in a real repo
- [ ] Landing page live with demo GIF
- [ ] Product Hunt listing drafted with tagline, description, and screenshots
