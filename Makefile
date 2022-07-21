commitHooks:
	pre-commit run --all-files

test:
	poetry run pytest tests

exportReqs:
	poetry export -o requirements.txt
	poetry export --dev -o requirements-dev.txt
