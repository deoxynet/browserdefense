# Demo GIF Generator

Generates an animated GIF showcasing BrowserDefense's workflow for the landing page.

## Requirements

- Built extension (`npm run build`)
- ffmpeg (`brew install ffmpeg`)

## Usage

```bash
npm run demo
```

This will:
1. Launch Chrome with the BrowserDefense extension loaded
2. Capture screenshots of each demo step
3. Convert screenshots to an animated GIF
4. Output to `website/assets/demo.gif`

## Demo Workflow

The GIF demonstrates:

1. **Threat Report** - SOC analyst reviews a phishing URL from threat intel
2. **Extension Active** - BrowserDefense popup shows protection is enabled
3. **IOC Added** - Confirmation that the threat was added to blocklist
4. **Block Page** - User attempts to visit the URL and is blocked
5. **Recent Blocks** - Popup shows the captured block event

## Customization

Edit `generate-demo.ts` to modify:

- `DEMO_CONFIG.viewport` - Screenshot dimensions
- `DEMO_CONFIG.frameDelay` - Time between frames (ms)
- `DEMO_CONFIG.phishingUrl` - The demo phishing URL
- `frames` array - Add/remove/modify captured steps

## Output

- **GIF**: `website/assets/demo.gif`
- **Frames**: `docs/demo/frames/` (intermediate PNGs)

Target: <5MB file size at 800px width.

## Troubleshooting

**"Extension not built"**: Run `npm run build` first

**"ffmpeg not found"**: Install with `brew install ffmpeg`

**GIF too large**: Reduce frame count or viewport size in config
