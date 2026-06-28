.PHONY: install dev serve init test lint clean docker-up docker-down

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

serve:
	keyhub serve

init:
	keyhub init

test:
	pytest -v

lint:
	ruff check keyhub

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf data/*.db data/*.db-*

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-init:
	docker compose run --rm keyhub keyhub init
