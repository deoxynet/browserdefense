.PHONY: build dev test clean

DIST := $(shell pwd)/dist

build:
	pnpm run build
	@echo ""
	@echo "Extension built in $(DIST)"
	@echo "Load in Chrome: chrome://extensions → Load unpacked → $(DIST)"

dev:
	pnpm run dev

test:
	pnpm test

test-e2e:
	pnpm run test:e2e

clean:
	rm -rf dist
