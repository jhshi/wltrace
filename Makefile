PKG=wltrace
VERSION=$(shell python -c "from wltrace.version import __version__; print __version__")


clean:
	find ./$(PKG) -name "*.pyc" -exec rm -rfv {} \;

test:
	tox

publish: clean test
	git tag -a $(VERSION) -m "v$(VERSION)" -f
	git push origin --tags
	python setup.py sdist upload -r pypi

.PHONY: test clean publish
