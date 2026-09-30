.PHONY: build ui hub test run

# The Hub as one binary, dashboard included.
build: ui hub

ui:
	cd ui && npm ci && npm run build

hub:
	go build -o bin/hub ./cmd/hub

# Unit and integration tests. The integration tests need HUB_TEST_DATABASE_URL
# (a database they may wipe); it is read from .env when set there.
test:
	go vet ./...
	set -a; [ -f .env ] && . ./.env; set +a; go test -p 1 -count=1 ./...
	cd ui && npm run typecheck

# Against the real Asgardeo, settings from .env.
run: build
	./bin/hub
