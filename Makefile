pretty:
	poetry install --no-root --with dev
	poetry run ruff format
	poetry run ruff check --fix
	poetry run ruff format

lint:
	poetry install --no-root --with dev
	poetry run ruff check
	poetry run ruff format --check
