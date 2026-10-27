.PHONY: help install install-symlink install-pipx install-pip uninstall test clean

help:
	@echo "targets:"
	@echo "  make install          # auto (pipx if available, else symlink)"
	@echo "  make install-symlink  # symlink to ~/.local/bin"
	@echo "  make install-pipx     # pipx install ."
	@echo "  make install-pip      # pip --user install"
	@echo "  make uninstall"
	@echo "  make test             # pytest"
	@echo "  make clean            # remove build artifacts"

install:
	./setup.sh

install-symlink:
	./setup.sh --symlink

install-pipx:
	./setup.sh --pipx

install-pip:
	./setup.sh --pip

uninstall:
	./setup.sh --uninstall

test:
	python3 -m pytest -v tests/

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__ tests/__pycache__