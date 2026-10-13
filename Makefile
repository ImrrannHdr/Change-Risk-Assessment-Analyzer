.PHONY: test lint demo package

test:
	pytest -q

lint:
	ruff check src tests

demo:
	python -m src.cli samples/sample_tfplan.json prod || true

package:
	mkdir -p dist/package
	pip install -r requirements.txt -t dist/package
	cp -r src dist/package/
	cd dist/package && zip -qr ../lambda.zip .

# Build by Imran Haider
