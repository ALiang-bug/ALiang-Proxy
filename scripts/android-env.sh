#!/bin/sh
# Source this file from project-root build scripts; device users never need it.
REPO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export JAVA_HOME="${JAVA_HOME:-$REPO_DIR/.tools/android-jdk/Contents/Home}"
export ANDROID_HOME="${ANDROID_HOME:-$REPO_DIR/.tools/android-sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/29.0.14206865}"
export GRADLE_USER_HOME="$REPO_DIR/.cache/android-gradle-home"
export GOCACHE="$REPO_DIR/.cache/go-build"
export GOMODCACHE="$REPO_DIR/.cache/go-mod"
export GOPATH="$REPO_DIR/.tools/go-path"
export GOTOOLCHAIN=go1.26.11
export PATH="$JAVA_HOME/bin:$REPO_DIR/.tools/bin:/opt/homebrew/opt/go@1.25/bin:$PATH"
