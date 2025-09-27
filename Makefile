install:
	pip install -r requirements.txt

test:
	# py.test tests
	@echo "No tests (yet)"

clean:
	find src tests \
		-type d -name __pycache__ -delete \
		-or -type f -name '*.py[cod]' -delete \
		-or -type f -name '*$py.class' -delete

.PHONY: init test