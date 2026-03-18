# Product Hunt Screenshot Guide

Capture these 5 screenshots for the Product Hunt listing. Recommended size: 1270x760.

## Screenshot 1: Landing Page Hero
- URL: `https://vibecheck.dev/landing`
- Show: Full hero section with "Stop shipping hackable code", the stat badge, CTA buttons, and terminal mockup
- This is your PH thumbnail/gallery image #1

## Screenshot 2: Terminal Scan Results
- Run: `npx vibecheck scan test-app --no-ai`
- Capture the terminal showing the color-coded output with severity badges, code snippets, and fix suggestions
- Best captured with a tool like [iTerm2](https://iterm2.com) with a dark theme

## Screenshot 3: Security Dashboard
- URL: `https://vibecheck.dev/` (logged in)
- Show: Stats row, vulnerability trend chart, and scan history table
- Gallery image #3

## Screenshot 4: Scan Detail with Finding Cards
- URL: `https://vibecheck.dev/scans/scan-1`
- Scroll to show the Stripe webhook finding with code snippet and green fix box
- Gallery image #4

## Screenshot 5: Pricing Page
- URL: `https://vibecheck.dev/landing#pricing`
- Show: Free vs Pro side-by-side pricing cards
- Gallery image #5

## Demo GIF/Video

For the animated demo, use one of these tools:

### Option A: VHS (recommended for terminal recording)
```bash
brew install vhs
```

Create `demo.tape`:
```
Output assets/demo.gif
Set FontSize 16
Set Width 900
Set Height 500
Set Theme "Dracula"

Type "npx vibecheck scan ."
Enter
Sleep 3s
```

Run: `vhs demo.tape`

### Option B: asciinema + svg-term
```bash
brew install asciinema
npm install -g svg-term-cli

# Record
asciinema rec demo.cast

# Convert to SVG
svg-term --in demo.cast --out assets/demo.svg --window
```

### Option C: Screen recording
Use QuickTime (Cmd+Shift+5) to record a 30-second video:
1. Open terminal
2. `cd` to a project directory
3. Run `npx vibecheck scan .`
4. Show the results scrolling by
5. Convert to GIF with: `ffmpeg -i demo.mov -vf "fps=10,scale=800:-1" assets/demo.gif`
