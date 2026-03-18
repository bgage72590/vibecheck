import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "VibeCheck — AI Security Scanner for Vibe-Coded Apps",
  description:
    "Find vulnerabilities in your AI-generated code before attackers do. One command. Plain-English results. Built for Cursor, Lovable, Bolt, and Replit users.",
};

function NavBar() {
  return (
    <nav className="flex items-center justify-between max-w-6xl mx-auto px-4 sm:px-6 py-4 sm:py-5">
      <span className="text-xl font-bold text-cyan-400">vibecheck</span>
      <div className="flex items-center gap-3 sm:gap-6">
        <a href="#features" className="text-sm text-gray-400 hover:text-white transition hidden sm:inline">Features</a>
        <a href="#pricing" className="text-sm text-gray-400 hover:text-white transition hidden sm:inline">Pricing</a>
        <a href="https://github.com/vibecheck/vibecheck" target="_blank" rel="noopener noreferrer" className="text-sm text-gray-400 hover:text-white transition hidden md:inline">GitHub</a>
        <a
          href="/auth/login"
          className="text-sm px-4 py-2 rounded-lg bg-cyan-500 text-black font-semibold hover:bg-cyan-400 transition"
        >
          Sign In
        </a>
      </div>
    </nav>
  );
}

function Hero() {
  return (
    <section className="max-w-4xl mx-auto px-4 sm:px-6 pt-12 sm:pt-20 pb-12 sm:pb-16 text-center">
      <div className="inline-block px-3 sm:px-4 py-1.5 rounded-full bg-red-900/30 text-red-400 text-xs sm:text-sm font-medium mb-4 sm:mb-6">
        45% of AI-generated code contains security vulnerabilities
      </div>
      <h1 className="text-3xl sm:text-5xl md:text-6xl font-bold leading-tight mb-4 sm:mb-6">
        Stop shipping
        <br />
        <span className="text-red-400">hackable</span> code
      </h1>
      <p className="text-base sm:text-xl text-gray-400 max-w-2xl mx-auto mb-8 sm:mb-10 leading-relaxed px-2">
        One command finds vulnerabilities in your AI-generated code.
        Plain-English results. Fix suggestions included. Built for Cursor,
        Lovable, Bolt, and Replit users.
      </p>
      <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-8 sm:mb-12 px-2">
        <code className="bg-[#1a1a2e] border border-gray-700 rounded-xl px-4 sm:px-6 py-3 sm:py-3.5 text-base sm:text-lg font-mono text-cyan-400 w-full sm:w-auto text-center">
          npx vibecheck scan .
        </code>
        <span className="text-gray-600">or</span>
        <a
          href="#pricing"
          className="px-6 py-3 sm:py-3.5 rounded-xl bg-cyan-500 text-black font-bold text-base sm:text-lg hover:bg-cyan-400 transition w-full sm:w-auto text-center"
        >
          Get Started Free
        </a>
      </div>

      {/* Terminal mockup */}
      <div className="max-w-2xl mx-auto bg-[#12121f] rounded-xl sm:rounded-2xl overflow-hidden border border-gray-800 text-left shadow-2xl mx-2 sm:mx-auto">
        <div className="flex items-center gap-2 px-4 py-3 bg-[#0d0d18] border-b border-gray-800">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
          <span className="ml-2 text-xs text-gray-500">terminal</span>
        </div>
        <div className="p-5 font-mono text-sm leading-relaxed">
          <p className="text-gray-500">$ npx vibecheck scan .</p>
          <p className="text-gray-500 mt-2">  vibecheck — security scan results</p>
          <p className="text-gray-600 mt-1">  ──────────────────────────────────────</p>
          <p className="mt-2">
            <span className="text-white">  Found </span>
            <span className="text-white font-bold">11</span>
            <span className="text-white"> issues: </span>
            <span className="bg-red-600 text-white px-1.5 py-0.5 rounded text-xs font-bold">7 CRITICAL</span>
            <span className="text-gray-500"> | </span>
            <span className="text-orange-400 font-bold">3 high</span>
            <span className="text-gray-500"> | </span>
            <span className="text-yellow-400">1 medium</span>
          </p>
          <p className="text-gray-500 mt-1">  Scanned 47 files in 2.3s</p>
          <p className="mt-4">
            <span className="bg-red-600 text-white px-1.5 py-0.5 rounded text-xs font-bold"> CRITICAL </span>
            <span className="text-gray-500"> [VC005] </span>
            <span className="text-white font-semibold">Unprotected Stripe Webhook</span>
          </p>
          <p className="text-cyan-400 text-xs mt-1">  server.js:39</p>
          <p className="text-gray-400 text-xs mt-2">  Attackers can fake payment events and mark</p>
          <p className="text-gray-400 text-xs">  orders as paid without actually paying.</p>
          <p className="text-green-400 text-xs mt-2">  Fix: Use stripe.webhooks.constructEvent()</p>
        </div>
      </div>
    </section>
  );
}

function Features() {
  const features = [
    {
      icon: "~",
      title: "10 Vibe-Code Rules",
      desc: "Purpose-built for AI-generated code. Catches hardcoded secrets, missing auth, Supabase RLS bypass, unprotected Stripe webhooks, SQL injection, XSS, and more.",
    },
    {
      icon: "*",
      title: "AI-Powered Analysis",
      desc: "Claude analyzes your code in context, finds issues static rules miss, and explains every vulnerability in plain English with fix instructions.",
    },
    {
      icon: "#",
      title: "One Command",
      desc: "npx vibecheck scan . — no config, no setup, no account required. Works with any JS/TS/Python project out of the box.",
    },
    {
      icon: ">",
      title: "CI/CD Ready",
      desc: "GitHub Action with SARIF output. Findings appear in GitHub Security tab. Block PRs with critical vulnerabilities.",
    },
    {
      icon: "+",
      title: "Deep Scanning",
      desc: "Optionally integrates Semgrep (2000+ rules) and Gitleaks (secret detection) for enterprise-grade coverage.",
    },
    {
      icon: "!",
      title: "Built for Non-Experts",
      desc: 'No security jargon. Instead of "IDOR vulnerability via insecure direct object reference", we say "anyone can access other users\' data by changing the ID in the URL."',
    },
  ];

  return (
    <section id="features" className="max-w-6xl mx-auto px-4 sm:px-6 py-12 sm:py-20">
      <h2 className="text-2xl sm:text-3xl font-bold text-center mb-4">
        Security scanning that speaks your language
      </h2>
      <p className="text-gray-400 text-center mb-8 sm:mb-12 max-w-2xl mx-auto">
        Built by security engineers for people who aren&apos;t security engineers.
      </p>
      <div className="grid md:grid-cols-3 gap-6">
        {features.map((f) => (
          <div
            key={f.title}
            className="bg-[#1a1a2e] rounded-xl p-6 border border-gray-800/50 hover:border-cyan-800/50 transition"
          >
            <div className="text-2xl mb-3 w-10 h-10 rounded-lg bg-cyan-900/30 flex items-center justify-center text-cyan-400 font-mono">
              {f.icon}
            </div>
            <h3 className="font-semibold text-lg mb-2">{f.title}</h3>
            <p className="text-gray-400 text-sm leading-relaxed">{f.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function SocialProof() {
  return (
    <section className="max-w-4xl mx-auto px-4 sm:px-6 py-12 sm:py-16">
      <div className="bg-[#1a1a2e] rounded-2xl p-8 border border-gray-800/50">
        <h2 className="text-2xl font-bold text-center mb-6">The problem is real</h2>
        <div className="grid sm:grid-cols-3 gap-8 text-center">
          <div>
            <div className="text-3xl font-bold text-red-400">45%</div>
            <p className="text-gray-400 text-sm mt-1">of AI-generated code has security vulnerabilities</p>
          </div>
          <div>
            <div className="text-3xl font-bold text-orange-400">5,600</div>
            <p className="text-gray-400 text-sm mt-1">vibe-coded apps scanned, 2,000+ vulnerabilities found</p>
          </div>
          <div>
            <div className="text-3xl font-bold text-yellow-400">80%</div>
            <p className="text-gray-400 text-sm mt-1">of devs wrongly believe AI code is more secure</p>
          </div>
        </div>
      </div>
    </section>
  );
}

function Pricing() {
  return (
    <section id="pricing" className="max-w-4xl mx-auto px-4 sm:px-6 py-12 sm:py-20">
      <h2 className="text-3xl font-bold text-center mb-4">Simple pricing</h2>
      <p className="text-gray-400 text-center mb-12">
        Start free. Upgrade when you need more.
      </p>
      <div className="grid sm:grid-cols-2 gap-6 max-w-2xl mx-auto">
        {/* Free */}
        <div className="bg-[#1a1a2e] rounded-2xl p-8 border border-gray-800/50">
          <h3 className="text-lg font-semibold mb-1">Free</h3>
          <div className="text-4xl font-bold mb-4">
            $0<span className="text-lg text-gray-500 font-normal">/mo</span>
          </div>
          <ul className="space-y-3 text-sm text-gray-400 mb-8">
            <li className="flex items-start gap-2">
              <span className="text-green-400 mt-0.5">+</span>
              3 scans per day
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-400 mt-0.5">+</span>
              All 10 security rules
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-400 mt-0.5">+</span>
              AI analysis (bring your own key)
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-400 mt-0.5">+</span>
              Terminal + JSON output
            </li>
          </ul>
          <code className="block text-center bg-[#12121f] rounded-lg py-3 text-sm text-cyan-400 font-mono">
            npx vibecheck scan .
          </code>
        </div>

        {/* Pro */}
        <div className="bg-[#1a1a2e] rounded-2xl p-8 border-2 border-cyan-500/50 relative">
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 bg-cyan-500 text-black text-xs font-bold rounded-full">
            POPULAR
          </div>
          <h3 className="text-lg font-semibold mb-1">Pro</h3>
          <div className="text-4xl font-bold mb-4">
            $29<span className="text-lg text-gray-500 font-normal">/mo</span>
          </div>
          <ul className="space-y-3 text-sm text-gray-400 mb-8">
            <li className="flex items-start gap-2">
              <span className="text-cyan-400 mt-0.5">+</span>
              Unlimited scans
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cyan-400 mt-0.5">+</span>
              Scan history dashboard
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cyan-400 mt-0.5">+</span>
              SARIF output for GitHub
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cyan-400 mt-0.5">+</span>
              GitHub Action integration
            </li>
            <li className="flex items-start gap-2">
              <span className="text-cyan-400 mt-0.5">+</span>
              Priority support
            </li>
          </ul>
          <a
            href="/auth/login"
            className="block text-center bg-cyan-500 text-black font-bold rounded-lg py-3 hover:bg-cyan-400 transition"
          >
            Start Free Trial
          </a>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="max-w-6xl mx-auto px-4 sm:px-6 py-8 sm:py-12 border-t border-gray-800">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <span className="text-cyan-400 font-bold">vibecheck</span>
        <p className="text-sm text-gray-500">
          Stop being the next Leo. Scan your code before you ship.
        </p>
        <div className="flex gap-6 text-sm text-gray-500">
          <a href="https://github.com/vibecheck/vibecheck" target="_blank" rel="noopener noreferrer" className="hover:text-white transition">GitHub</a>
          <a href="mailto:hello@vibecheck.dev" rel="noopener noreferrer" className="hover:text-white transition">Contact</a>
        </div>
      </div>
    </footer>
  );
}

export default function LandingPage() {
  return (
    <div className="min-h-screen">
      <NavBar />
      <Hero />
      <SocialProof />
      <Features />
      <Pricing />
      <Footer />
    </div>
  );
}
