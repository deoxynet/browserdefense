#!/usr/bin/env node
/**
 * Generate PNG icons from SVG source
 * Creates icons at 16x16, 48x48, and 128x128 for Chrome extension
 * Also creates a 300x100 promotional banner
 */

import sharp from 'sharp';
import { readFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const iconsDir = join(__dirname, '..', 'icons');

// Ensure icons directory exists
mkdirSync(iconsDir, { recursive: true });

// Read SVG source
const svgPath = join(iconsDir, 'icon.svg');
const svgBuffer = readFileSync(svgPath);

// Icon sizes for Chrome extension
const sizes = [16, 48, 128];

async function generateIcons() {
  console.log('Generating extension icons...');

  for (const size of sizes) {
    const outputPath = join(iconsDir, `icon${size}.png`);
    await sharp(svgBuffer)
      .resize(size, size)
      .png()
      .toFile(outputPath);
    console.log(`  Created: icon${size}.png`);
  }

  console.log('Icons generated successfully!');
}

async function generateBanner() {
  console.log('Generating promotional banner...');

  // Create a 300x100 banner with the icon and text
  const bannerWidth = 300;
  const bannerHeight = 100;
  const iconSize = 64;

  // First resize the icon
  const iconBuffer = await sharp(svgBuffer)
    .resize(iconSize, iconSize)
    .png()
    .toBuffer();

  // Create the banner background
  const banner = await sharp({
    create: {
      width: bannerWidth,
      height: bannerHeight,
      channels: 4,
      background: { r: 37, g: 99, b: 235, alpha: 1 } // #2563eb blue
    }
  })
    .composite([
      {
        input: iconBuffer,
        left: 20,
        top: Math.floor((bannerHeight - iconSize) / 2)
      }
    ])
    .png()
    .toFile(join(iconsDir, 'banner300x100.png'));

  console.log('  Created: banner300x100.png');
  console.log('Banner generated successfully!');
}

async function main() {
  try {
    await generateIcons();
    await generateBanner();
    console.log('\nAll assets generated!');
  } catch (error) {
    console.error('Error generating assets:', error);
    process.exit(1);
  }
}

main();
