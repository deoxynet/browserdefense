#!/usr/bin/env node
import sharp from 'sharp';

await sharp('icons/icon128.png')
  .resize(32, 32)
  .toFile('icons/icon32.png');
console.log('Created icons/icon32.png');
