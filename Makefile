# Kyber-PQC Build Automation
PYTHON := python3
PIP := pip3

.PHONY: all install build test lint clean test-c test-go test-rust \
	conan-create conan-remote conan-upload publish-bajpai \
	brew-test docker-build docker-push-bajpai

all: install test

install:
	$(PIP) install -U pip wheel
	$(PIP) install -e ".[dev]"

build:
	$(PYTHON) -m build --wheel

test: test-python test-c test-go test-rust

test-python:
	$(PYTHON) -m pytest src/tests/ --cov=kyber_pqc --cov-report=term-missing

test-c:
	$(MAKE) -C c test

test-go:
	$(MAKE) -C c lib
	cd go && CGO_ENABLED=1 go test ./...

test-rust:
	cargo test --workspace

lint:
	$(PYTHON) -m flake8 src/
	$(PYTHON) -m mypy src/kyber_pqc/

conan-create:
	conan profile detect --force
	conan create . --build=missing

CONAN_REMOTE ?= bajpai
CONAN_URL ?= https://conan.bajpailabs.com
DOCKER_REGISTRY ?= docker.bajpailabs.com
DOCKER_REPO ?= repository/bajpailabs-docker
DOCKER_IMAGE ?= $(DOCKER_REGISTRY)/$(DOCKER_REPO)/kyber-pqc

conan-remote:
	conan remote add $(CONAN_REMOTE) $(CONAN_URL) --force
	@test -n "$(BAJPAILABS_REGISTRY_USER)" || (echo "Set BAJPAILABS_REGISTRY_USER" && exit 1)
	conan remote login $(CONAN_REMOTE) $(BAJPAILABS_REGISTRY_USER) \
		-p $(BAJPAILABS_REGISTRY_PASSWORD)

conan-upload: conan-create
	conan upload "kyber-pqc/*" -r $(CONAN_REMOTE) --confirm

publish-bajpai:
	bash scripts/publish-bajpai.sh

docker-push-bajpai: docker-build
	@test -n "$(BAJPAILABS_REGISTRY_USER)" || (echo "Set BAJPAILABS_REGISTRY_USER" && exit 1)
	echo "$(BAJPAILABS_REGISTRY_PASSWORD)" | docker login $(DOCKER_REGISTRY) \
		-u "$(BAJPAILABS_REGISTRY_USER)" --password-stdin
	docker tag kyber-pqc:local $(DOCKER_IMAGE):latest
	docker push $(DOCKER_IMAGE):latest

brew-test:
	cmake -S c -B c/build -DCMAKE_BUILD_TYPE=Release -DPROJECT_VERSION=2.1.1
	cmake --build c/build
	./c/build/kyber-pqc version
	brew style Formula/kyber-pqc.rb

docker-build:
	docker build -t kyber-pqc:local .

clean:
	rm -rf build/ dist/ .coverage .pytest_cache/ htmlcov/
	rm -rf src/kyber_pqc.egg-info/ *.egg-info/
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	$(MAKE) -C c clean
