.PHONY: $(MAKECMDGOALS) all
.DEFAULT_GOAL := help
RUN := $(shell realpath $(shell dirname $(firstword $(MAKEFILE_LIST)))/scripts/run.sh)

# Begin OS detection
ifeq ($(OS),Windows_NT) # is Windows_NT on XP, 2000, 7, Vista, 10...
    export OPERATING_SYSTEM := Windows
	export RUST_TARGET ?= "x86_64-unknown-windows-msvc"
    export DEFAULT_FEATURES = default-msvc
else
    export OPERATING_SYSTEM := $(shell uname)  # same as "uname -s"
	export RUST_TARGET ?= "x86_64-unknown-linux-gnu"
    export DEFAULT_FEATURES = default
endif

# Override this with any scopes for testing/benching.
export SCOPE ?= ""
# Override to false to disable autospawning services on integration tests.
export AUTOSPAWN ?= true
# Override to control if services are turned off after integration tests.
export AUTODESPAWN ?= ${AUTOSPAWN}
# Override to true for a bit more log output in your environment building (more coming!)
export VERBOSE ?= false
# Override to set a different Rust toolchain
export RUST_TOOLCHAIN ?= $(shell cat rust-toolchain)
# Override the container tool.
# TODO: We're working on first class `podman` support for integration tests! We need to move away from compose though: https://github.com/containers/podman-compose/issues/125
export CONTAINER_TOOL ?= docker
# Override this to automatically enter a container containing the correct, full, official build environment for Vector, ready for development
export ENVIRONMENT ?= false
# The upstream container we publish artifacts to on a successful master build.
export ENVIRONMENT_UPSTREAM ?= docker.pkg.github.com/timberio/vector/environment
# Override to disable building the container, having it pull from the Github packages repo instead
# TODO: Disable this by default. Blocked by `docker pull` from Github Packages requiring authenticated login
export ENVIRONMENT_AUTOBUILD ?= true
# Override this when appropriate to disable a TTY being available in commands with `ENVIRONMENT=true` (Useful for CI, but CI uses Nix!)
export ENVIRONMENT_TTY ?= true

 # Deprecated.
export USE_CONTAINER ?= $(CONTAINER_TOOL)

FORMATTING_BEGIN_YELLOW = \033[0;33m
FORMATTING_BEGIN_BLUE = \033[36m
FORMATTING_END = \033[0m

help:
	@printf -- "${FORMATTING_BEGIN_BLUE}                                      __   __  __${FORMATTING_END}\n"
	@printf -- "${FORMATTING_BEGIN_BLUE}                                      \ \ / / / /${FORMATTING_END}\n"
	@printf -- "${FORMATTING_BEGIN_BLUE}                                       \ V / / / ${FORMATTING_END}\n"
	@printf -- "${FORMATTING_BEGIN_BLUE}                                        \_/  \/  ${FORMATTING_END}\n"
	@printf -- "\n"
	@printf -- "                                      V E C T O R\n"
	@printf -- "\n"
	@printf -- "---------------------------------------------------------------------------------------\n"
	@printf -- "Nix user? You can use ${FORMATTING_BEGIN_YELLOW}\`direnv allow .\`${FORMATTING_END} or ${FORMATTING_BEGIN_YELLOW}\`nix-shell --pure\`${FORMATTING_END}\n"
	@printf -- "Want to use ${FORMATTING_BEGIN_YELLOW}\`docker\`${FORMATTING_END} or ${FORMATTING_BEGIN_YELLOW}\`podman\`${FORMATTING_END}? See ${FORMATTING_BEGIN_YELLOW}\`ENVIRONMENT=true\`${FORMATTING_END} commands. (Default ${FORMATTING_BEGIN_YELLOW}\`CONTAINER_TOOL=docker\`${FORMATTING_END})\n"
	@printf -- "\n"
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make ${FORMATTING_BEGIN_BLUE}<target>${FORMATTING_END}\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  ${FORMATTING_BEGIN_BLUE}%-46s${FORMATTING_END} %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Environment
# We use a volume here as non-Linux hosts are extremely slow to share disks, and Linux hosts tend to get permissions clobbered.
define ENVIRONMENT_EXEC
	@echo "Entering environment..."
	@mkdir -p target
	$(CONTAINER_TOOL) run \
			--name vector-environment \
			--rm \
			$(if $(findstring true,$(ENVIRONMENT_TTY)),--tty,) \
			--init \
			--interactive \
			--env INSIDE_ENVIRONMENT=true \
			--network host \
			--mount type=bind,source=${PWD},target=/vector \
			--mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
			--mount type=volume,source=vector-target,target=/vector/target \
			--mount type=volume,source=vector-cargo-cache,target=/root/.cargo \
			$(ENVIRONMENT_UPSTREAM)
endef

define ENVIRONMENT_COPY_ARTIFACTS
	@echo "Copying artifacts off volumes... (Docker errors below are totally okay)"
	@mkdir -p ./target/release
	@mkdir -p ./target/debug
	@mkdir -p ./target/criterion
	@$(CONTAINER_TOOL) rm -f vector-build-outputs || true
	@$(CONTAINER_TOOL) run \
		-d \
		-v vector-target:/target \
		--name vector-build-outputs \
		busybox true
	@$(CONTAINER_TOOL) cp vector-build-outputs:/target/release/vector ./target/release/ || true
	@$(CONTAINER_TOOL) cp vector-build-outputs:/target/debug/vector ./target/debug/ || true
	@$(CONTAINER_TOOL) cp vector-build-outputs:/target/criterion ./target/criterion || true
	@$(CONTAINER_TOOL) rm -f vector-build-outputs
endef


ifeq ($(ENVIRONMENT_AUTOBUILD), true)
define ENVIRONMENT_PREPARE
	@echo "Building the environment. (ENVIRONMENT_AUTOBUILD=true) This may take a few minutes..."
	$(CONTAINER_TOOL) build \
		$(if $(findstring true,$(VERBOSE)),,--quiet) \
		--tag $(ENVIRONMENT_UPSTREAM) \
		--file scripts/environment/Dockerfile \
		.
endef
else
define ENVIRONMENT_PREPARE
	$(CONTAINER_TOOL) pull $(ENVIRONMENT_UPSTREAM)
endef
endif


environment: ## Enter a full Vector dev shell in $CONTAINER_TOOL, binding this folder to the container.
	${ENVIRONMENT_PREPARE}
	@export ENVIRONMENT_TTY=true
	${ENVIRONMENT_EXEC}

environment-prepare: ## Prepare the Vector dev shell using $CONTAINER_TOOL.
	${ENVIRONMENT_PREPARE}

environment-clean: ## Clean the Vector dev shell using $CONTAINER_TOOL.
	@$(CONTAINER_TOOL) volume rm -f vector-target vector-cargo-cache
	@$(CONTAINER_TOOL) rmi $(ENVIRONMENT_UPSTREAM) || true

environment-push: environment-prepare ## Publish a new version of the container image.
	$(CONTAINER_TOOL) push $(ENVIRONMENT_UPSTREAM)

##@ Building
build: ## Build the project in release mode (Supports `ENVIRONMENT=true`)
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make build
	${ENVIRONMENT_COPY_ARTIFACTS}
else
	cargo build --release --no-default-features --features ${DEFAULT_FEATURES}
endif

build-dev: ## Build the project in development mode (Supports `ENVIRONMENT=true`)
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make build-dev
	${ENVIRONMENT_COPY_ARTIFACTS}
else
	cargo build --no-default-features --features ${DEFAULT_FEATURES}
endif

build-all: build-x86_64-unknown-linux-musl build-armv7-unknown-linux-musleabihf build-aarch64-unknown-linux-musl ## Build the project in release mode for all supported platforms

build-x86_64-unknown-linux-gnu: ## Build dynamically linked binary in release mode for the x86_64 architecture
	$(RUN) build-x86_64-unknown-linux-gnu

build-x86_64-unknown-linux-musl: ## Build static binary in release mode for the x86_64 architecture
	$(RUN) build-x86_64-unknown-linux-musl

build-armv7-unknown-linux-musleabihf: load-qemu-binfmt ## Build static binary in release mode for the armv7 architecture
	$(RUN) build-armv7-unknown-linux-musleabihf

build-aarch64-unknown-linux-musl: load-qemu-binfmt ## Build static binary in release mode for the aarch64 architecture
	$(RUN) build-aarch64-unknown-linux-musl

##@ Testing (Supports `ENVIRONMENT=true`)

test: ## Run the test suite
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test
	${ENVIRONMENT_COPY_ARTIFACTS}
else
	cargo test --no-default-features --features ${DEFAULT_FEATURES} ${SCOPE} -- --nocapture
endif

test-all: test-behavior test-integration test-unit ## Runs all tests, unit, behaviorial, and integration.

test-behavior: ## Runs behaviorial test
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-behavior
	${ENVIRONMENT_COPY_ARTIFACTS}
else
	cargo run -- test tests/behavior/**/*.toml
endif

test-integration: ## Runs all integration tests
test-integration: test-integration-aws test-integration-clickhouse test-integration-docker test-integration-elasticsearch
test-integration: test-integration-gcp test-integration-influxdb test-integration-kafka test-integration-loki
test-integration: test-integration-pulsar test-integration-splunk

test-integration-aws: ## Runs Clickhouse integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}fre
	${ENVIRONMENT_EXEC} make test-integration-aws
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-aws; \
		sleep 5 # Many services are very lazy... Give them a sec... \
	fi
	cargo test --no-default-features --features aws-integration-tests ::aws_cloudwatch_logs:: -- --nocapture
	cargo test --no-default-features --features aws-integration-tests ::aws_cloudwatch_metrics:: -- --nocapture
	cargo test --no-default-features --features aws-integration-tests ::aws_kinesis_firehose:: -- --nocapture
	cargo test --no-default-features --features aws-integration-tests ::aws_kinesis_streams:: -- --nocapture
	cargo test --no-default-features --features aws-integration-tests ::aws_s3:: -- --nocapture
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

test-integration-clickhouse: ## Runs Clickhouse integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-integration-clickhouse
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-clickhouse; \
		sleep 5 # Many services are very lazy... Give them a sec... \
	fi
	cargo test --no-default-features --features clickhouse-integration-tests ::clickhouse:: -- --nocapture
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

test-integration-docker: ## Runs Docker integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-integration-docker
else
	cargo test --no-default-features --features docker-integration-tests ::docker:: -- --nocapture
endif

test-integration-elasticsearch: ## Runs Elasticsearch integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-integration-elasticsearch
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-elasticsearch; \
		sleep 20 # Elasticsearch is incredibly slow to start up, be very generous... \
	fi
	cargo test --no-default-features --features es-integration-tests ::elasticsearch:: -- --nocapture
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

test-integration-gcp: ## Runs GCP integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-integration-gcp
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-gcp; \
		sleep 5 # Many services are very lazy... Give them a sec... \
	fi
	cargo test --no-default-features --features gcp-integration-tests ::gcp:: -- --nocapture
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

test-integration-influxdb: ## Runs Kafka integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-integration-influxdb
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-influxdb; \
		sleep 5 # Many services are very lazy... Give them a sec... \
	fi
	cargo test --no-default-features --features influxdb-integration-tests ::influxdb::integration_tests:: -- --nocapture
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

test-integration-kafka: ## Runs Kafka integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-integration-kafka
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-kafka; \
		sleep 5 # Many services are very lazy... Give them a sec... \
	fi
	cargo test --no-default-features --features kafka-integration-tests ::kafka:: -- --nocapture
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

test-integration-loki: ## Runs Loki integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-integration-loki
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-loki; \
		sleep 5 # Many services are very lazy... Give them a sec... \
	fi
	cargo test --no-default-features --features loki-integration-tests ::loki:: -- --nocapture
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

test-integration-pulsar: ## Runs Pulsar integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-integration-pulsar
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-pulsar; \
		sleep 5 # Many services are very lazy... Give them a sec... \
	fi
	cargo test --no-default-features --features pulsar-integration-tests ::pulsar:: -- --nocapture
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

test-integration-splunk: ## Runs Splunk integration tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-integration-splunk
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-splunk; \
		sleep 5 # Many services are very lazy... Give them a sec... \
	fi
	cargo test --no-default-features --features splunk-integration-tests ::splunk:: -- --nocapture
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

PACKAGE_DEB_USE_CONTAINER ?= "$(USE_CONTAINER)"
test-integration-kubernetes: ## Runs Kubernetes integration tests (Sorry, no `ENVIRONMENT=true` support)
	PACKAGE_DEB_USE_CONTAINER="$(PACKAGE_DEB_USE_CONTAINER)" USE_CONTAINER=none $(RUN) test-integration-kubernetes

test-shutdown: ## Runs shutdown tests
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make test-shutdown
else
	if $(AUTOSPAWN); then \
		$(CONTAINER_TOOL)-compose up -d dependencies-kafka; \
		sleep 5 # Many services are very lazy... Give them a sec... \
	fi
	cargo test --features shutdown-tests  --test shutdown -- --test-threads 4
	if $(AUTODESPAWN); then \
		$(CONTAINER_TOOL)-compose stop; \
	fi
endif

##@ Benching (Supports `ENVIRONMENT=true`)

bench: ## Run benchmarks in /benches
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make bench
	${ENVIRONMENT_COPY_ARTIFACTS}
else
	cargo bench --no-default-features --features ${DEFAULT_FEATURES} ${SCOPE}
endif

##@ Checking (Supports `ENVIRONMENT=true`)

check: ## Run prerequisite code checks
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check
else
	cargo check --all --no-default-features --features ${DEFAULT_FEATURES}
endif

check-all: check-fmt check-clippy check-style check-markdown check-generate check-blog check-version check-examples check-component-features check-scripts ## Check everything

check-component-features: ## Check that all component features are setup properly
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check-component-features
else
	./scripts/check-component-features.sh
endif

check-clippy: ## Check code with Clippy
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check-clippy
else
	cargo clippy --workspace --all-targets -- -D warnings
endif

check-fmt: ## Check that all files are formatted properly
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check-fmt
else
	./scripts/check-fmt.sh
endif

check-style: ## Check that all files are styled properly
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check-style
else
	./scripts/check-style.sh
endif

check-markdown: ## Check that markdown is styled properly
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check-markdown
else
	@echo "This requires yarn have been run in the website/ dir!"
	./website/node_modules/.bin/markdownlint .
endif

check-generate: ## Check that no files are pending generation
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check-generate
else
	./scripts/check-generate.sh
endif


check-version: ## Check that Vector's version is correct accounting for recent changes
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check-version
else
	./scripts/check-version.rb
endif

check-examples: ## Check that the config/examples files are valid
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check-examples
else
	cargo run -- validate --topology --deny-warnings ./config/examples/*.toml
endif

check-scripts: ## Check that scipts do not have common mistakes
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make check-scripts
else
	./scripts/check-scripts.sh
endif

##@ Packaging

package-all: package-archive-all package-deb-all package-rpm-all ## Build all packages

package-x86_64-unknown-linux-musl-all: package-archive-x86_64-unknown-linux-musl package-deb-x86_64 package-rpm-x86_64 # Build all x86_64 MUSL packages


package-x86_64-unknown-linux-musl-all: package-archive-x86_64-unknown-linux-musl # Build all x86_64 MUSL packages

package-x86_64-unknown-linux-gnu-all: package-archive-x86_64-unknown-linux-gnu package-deb-x86_64 package-rpm-x86_64 # Build all x86_64 GNU packages

package-armv7-unknown-linux-musleabihf-all: package-archive-armv7-unknown-linux-musleabihf package-deb-armv7 package-rpm-armv7  # Build all armv7 MUSL packages

package-aarch64-unknown-linux-musl-all: package-archive-aarch64-unknown-linux-musl package-deb-aarch64 package-rpm-aarch64  # Build all aarch64 MUSL packages

# archives

package-archive: build ## Build the Vector archive
	$(RUN) package-archive

package-archive-all: package-archive-x86_64-unknown-linux-musl package-archive-x86_64-unknown-linux-gnu package-archive-armv7-unknown-linux-musleabihf package-archive-aarch64-unknown-linux-musl ## Build all archives

package-archive-x86_64-unknown-linux-musl: build-x86_64-unknown-linux-musl ## Build the x86_64 archive
	$(RUN) package-archive-x86_64-unknown-linux-musl

package-archive-x86_64-unknown-linux-gnu: build-x86_64-unknown-linux-gnu ## Build the x86_64 archive
	$(RUN) package-archive-x86_64-unknown-linux-gnu

package-archive-armv7-unknown-linux-musleabihf: build-armv7-unknown-linux-musleabihf ## Build the armv7 archive
	$(RUN) package-archive-armv7-unknown-linux-musleabihf

package-archive-aarch64-unknown-linux-musl: build-aarch64-unknown-linux-musl ## Build the aarch64 archive
	$(RUN) package-archive-aarch64-unknown-linux-musl

# debs

package-deb: ## Build the deb package
	$(RUN) package-deb

package-deb-all: package-deb-x86_64 package-deb-armv7 package-deb-aarch64 ## Build all deb packages

package-deb-x86_64: package-archive-x86_64-unknown-linux-gnu ## Build the x86_64 deb package
	$(RUN) package-deb-x86_64

package-deb-armv7: package-archive-armv7-unknown-linux-musleabihf ## Build the armv7 deb package
	$(RUN) package-deb-armv7

package-deb-aarch64: package-archive-aarch64-unknown-linux-musl  ## Build the aarch64 deb package
	$(RUN) package-deb-aarch64

# rpms

package-rpm: ## Build the rpm package
	$(RUN) package-rpm

package-rpm-all: package-rpm-x86_64 package-rpm-armv7 package-rpm-aarch64 ## Build all rpm packages

package-rpm-x86_64: package-archive-x86_64-unknown-linux-gnu ## Build the x86_64 rpm package
	$(RUN) package-rpm-x86_64

package-rpm-armv7: package-archive-armv7-unknown-linux-musleabihf ## Build the armv7 rpm package
	$(RUN) package-rpm-armv7

package-rpm-aarch64: package-archive-aarch64-unknown-linux-musl ## Build the aarch64 rpm package
	$(RUN) package-rpm-aarch64

##@ Releasing

release: release-prepare generate release-commit ## Release a new Vector version

release-commit: ## Commits release changes
	$(RUN) release-commit

release-docker: ## Release to Docker Hub
	$(RUN) release-docker

release-github: ## Release to Github
	$(RUN) release-github

release-homebrew: ## Release to timberio Homebrew tap
	$(RUN) release-homebrew

release-prepare: ## Prepares the release with metadata and highlights
	@scripts/release-prepare.sh

release-push: ## Push new Vector version
	@scripts/release-push.sh

release-rollback: ## Rollback pending release changes
	@scripts/release-rollback.sh

release-s3: ## Release artifacts to S3
	@scripts/release-s3.sh

sync-install: ## Sync the install.sh script for access via sh.vector.dev
	@aws s3 cp distribution/install.sh s3://sh.vector.dev --sse --acl public-read

##@ Verifying

verify: verify-rpm verify-deb ## Default target, verify all packages

verify-rpm: verify-rpm-amazonlinux-1 verify-rpm-amazonlinux-2 verify-rpm-centos-7 ## Verify all rpm packages

verify-rpm-amazonlinux-1: package-rpm-x86_64 ## Verify the rpm package on Amazon Linux 1
	$(RUN) verify-rpm-amazonlinux-1

verify-rpm-amazonlinux-2: package-rpm-x86_64 ## Verify the rpm package on Amazon Linux 2
	$(RUN) verify-rpm-amazonlinux-2

verify-rpm-centos-7: package-rpm-x86_64 ## Verify the rpm package on CentOS 7
	$(RUN) verify-rpm-centos-7

verify-deb: verify-deb-artifact-on-deb-8 verify-deb-artifact-on-deb-9 verify-deb-artifact-on-deb-10 verify-deb-artifact-on-ubuntu-16-04 verify-deb-artifact-on-ubuntu-18-04 verify-deb-artifact-on-ubuntu-19-04 ## Verify all deb packages

verify-deb-artifact-on-deb-8: package-deb-x86_64 ## Verify the deb package on Debian 8
	$(RUN) verify-deb-artifact-on-deb-8

verify-deb-artifact-on-deb-9: package-deb-x86_64 ## Verify the deb package on Debian 9
	$(RUN) verify-deb-artifact-on-deb-9

verify-deb-artifact-on-deb-10: package-deb-x86_64 ## Verify the deb package on Debian 10
	$(RUN) verify-deb-artifact-on-deb-10

verify-deb-artifact-on-ubuntu-16-04: package-deb-x86_64 ## Verify the deb package on Ubuntu 16.04
	$(RUN) verify-deb-artifact-on-ubuntu-16-04

verify-deb-artifact-on-ubuntu-18-04: package-deb-x86_64 ## Verify the deb package on Ubuntu 18.04
	$(RUN) verify-deb-artifact-on-ubuntu-18-04

verify-deb-artifact-on-ubuntu-19-04: package-deb-x86_64 ## Verify the deb package on Ubuntu 19.04
	$(RUN) verify-deb-artifact-on-ubuntu-19-04

verify-nixos:  ## Verify that Vector can be built on NixOS
	$(RUN) verify-nixos

##@ Website

generate:  ## Generates files across the repo using the data in /.meta
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make generate
else
	bundle exec --gemfile scripts/Gemfile ./scripts/generate.rb
endif

export ARTICLE ?= true
sign-blog: ## Sign newly added blog articles using GPG
	$(RUN) sign-blog

##@ Utility

build-ci-docker-images: ## Rebuilds all Docker images used in CI
	@scripts/build-ci-docker-images.sh

clean: environment-clean ## Clean everything
	cargo clean

fmt: ## Format code
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make fmt
else
	cargo fmt
	./scripts/check-style.sh --fix
endif

init-target-dir: ## Create target directory owned by the current user
	$(RUN) init-target-dir

load-qemu-binfmt: ## Load `binfmt-misc` kernel module which required to use `qemu-user`
	$(RUN) load-qemu-binfmt

signoff: ## Signsoff all previous commits since branch creation
	$(RUN) signoff

slim-builds: ## Updates the Cargo config to product disk optimized builds (for CI, not for users)
ifeq ($(ENVIRONMENT), true)
	${ENVIRONMENT_PREPARE}
	${ENVIRONMENT_EXEC} make slim-builds
else
	./scripts/slim-builds.sh
endif

target-graph: ## Display dependencies between targets in this Makefile
	@cd $(shell realpath $(shell dirname $(firstword $(MAKEFILE_LIST)))) && docker-compose run --rm target-graph $(TARGET)

version: ## Get the current Vector version
	$(RUN) version

git-hooks: ## Add Vector-local git hooks for commit sign-off
	@scripts/install-git-hooks.sh
