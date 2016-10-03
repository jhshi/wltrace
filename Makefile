PKG=wltrace
VERSION=$(shell python -c "from wltrace import __version__; print __version__")


clean:
	find ./$(PKG) -name "*.pyc" -exec rm -rfv {} \;

test:
	tox

publish: test
	git tag -a $(VERSION) -m "v$(VERSION)" -f
	git push origin --tags
	make clean
	python setup.py sdist upload -r pypi

.PHONY: test clean publish
