test:
	PURE=false ./node_modules/.bin/mocha --reporter list
	PURE=true ./node_modules/.bin/mocha --reporter list -t 30000

.PHONY: test