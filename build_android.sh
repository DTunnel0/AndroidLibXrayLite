#!/bin/bash

set -euo pipefail

ANDROID_HOME="${ANDROID_HOME:-/mnt/c/Users/glemy/AppData/Local/Android/Sdk}"
export ANDROID_HOME

ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-/home/dutra/libs/android-ndk-r28c}"
export ANDROID_NDK_HOME

ANDROID_API="${ANDROID_API:-21}"

AAR_FILENAME="${AAR_FILENAME:-libv2ray.aar}"
JAR_FILENAME="${JAR_FILENAME:-libv2ray-sources.jar}"

OUTPUT_DIR="${OUTPUT_DIR:-./build}"
OUTPUT_BUILD="${OUTPUT_DIR}/${AAR_FILENAME}"
JAR_OUTPUT="${OUTPUT_DIR}/${JAR_FILENAME}"

if [[ ! -d "${OUTPUT_DIR}" ]]; then
    echo "⚠️  Diretório de saída não encontrado. Gerando na pasta atual."
    OUTPUT_BUILD="./${AAR_FILENAME}"
    JAR_OUTPUT="./${JAR_FILENAME}"
fi

echo "📦 Gerando AAR..."
echo "  - ANDROID_NDK_HOME: ${ANDROID_NDK_HOME}"
echo "  - ANDROID_API: ${ANDROID_API}"
echo "  - OUTPUT_BUILD: ${OUTPUT_BUILD}"

gomobile bind \
    -v \
    -ldflags='-s -w' \
    -androidapi "${ANDROID_API}" \
    -target=android \
    -trimpath \
    -o "${OUTPUT_BUILD}" \
    ./

if [[ -f "${JAR_OUTPUT}" ]]; then
    echo "🧹 Limpando ${JAR_OUTPUT}"
    rm -f "${JAR_OUTPUT}"
fi

echo "✅ Build concluído com sucesso!"
