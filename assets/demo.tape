Output assets/demo.gif
Set FontSize 15
Set Width 900
Set Height 550
Set Theme "Dracula"
Set TypingSpeed 40ms
Set Padding 20

Type "# Scan your vibe-coded app for security vulnerabilities"
Enter
Sleep 500ms

Type "npx vibecheck scan . --no-ai"
Sleep 500ms
Enter
Sleep 4s

# Scroll to see results
Sleep 2s

Type "# Found 11 issues - let's see the JSON output"
Enter
Sleep 500ms

Type "npx vibecheck scan . --no-ai --format json | head -20"
Sleep 500ms
Enter
Sleep 3s

Type "# Fix the issues, then scan again!"
Enter
Sleep 2s
