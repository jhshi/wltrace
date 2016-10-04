PKG=wltrace
VERSION=$(shell python -c "from wltrace import __version__; print __version__")


clean:
	find ./$(PKG) -name "*.pyc" -exec rm -rfv {} \;

test:
	pytest tests/

publish:
	@echo "Releasing version $(VERSION)"
	tox
	git tag -a $(VERSION) -m "v$(VERSION)"
	git push origin --tags
	make clean
	python setup.py sdist upload -r pypi

.PHONY: test clean publish
