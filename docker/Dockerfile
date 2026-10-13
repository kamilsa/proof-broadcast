# syntax=docker/dockerfile:1
#
# Builds the `proof-broadcast-tree` binary and lays it onto a Shadow-capable
# base image. Built and run by `shadow-sim.py`. arm64 only — see proofsim.toml
# [docker].shadow_image.
ARG SHADOW_IMAGE=kamilsa/shadow-arm:tcpfix

# ── Stage 1: compile (release) ───────────────────────────────────────────────
FROM --platform=linux/arm64 rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY patch ./patch
COPY src ./src
RUN cargo build --release --bin proof-broadcast-tree

# ── Stage 2: binary on top of the Shadow base image ──────────────────────────
FROM --platform=linux/arm64 ${SHADOW_IMAGE}
COPY --from=build /src/target/release/proof-broadcast-tree /opt/proofsim/proof-broadcast-tree
