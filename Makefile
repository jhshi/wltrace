CWD=$(shell pwd)
PKG=wltrace
VERSION=$(shell python -c "from wltrace import __version__; print __version__")
DIST_DIR=$(CWD)/dist


clean:
	find ./$(PKG) -name "*.pyc" -exec rm -rfv {} \;

test:
	tox -r

publish: test
	# make sure git repo is clean
	git status --porcelain
	# make sure this version has not been published before
	test ! `find $(DIST_DIR) -name "*$(VERSION)*" -quit`
	@echo "Releasing version $(VERSION)"
	make clean
	python setup.py sdist upload -r pypi
	git tag -a $(VERSION) -m "v$(VERSION)"
	git push origin --tags

.PHONY: test clean publish
