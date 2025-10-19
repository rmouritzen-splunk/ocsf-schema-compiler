# TODO: Add linting and code formatting.

install:
	# TODO: Remove if not needed. For development-only requirements, use requirements-dev.txt.
	# TODO: If this is needed, create virtual environment if not already created, and activate it.
	pip install -r requirements.txt

test:
	# py.test tests
	@echo "No tests (yet)"

clean:
	find src tests \
		-type d -name __pycache__ -delete \
		-or -type f -name '*.py[cod]' -delete \
		-or -type f -name '*$py.class' -delete

cloc:
	cloc --exclude-dir=.venv,.idea .

.PHONY: init test