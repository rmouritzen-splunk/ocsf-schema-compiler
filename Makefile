# TODO: Add linting and code formatting.

.PHONY: tests
tests:
	cd src && python3 -m unittest discover -v -s ../tests

clean:
	find src tests \
		-type d -name __pycache__ -delete \
		-or -type f -name '*.py[cod]' -delete \
		-or -type f -name '*$py.class' -delete

cloc:
	cloc --exclude-dir=.venv,.idea .
