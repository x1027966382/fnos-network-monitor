#!/bin/bash
# FnOS Network Monitor FPK 打包脚本

set -e

APP_NAME="fnos-network-monitor"
APP_VERSION="1.0.0"
BUILD_DIR="$(pwd)"
DIST_DIR="${BUILD_DIR}/dist"

echo "🔨 开始构建 ${APP_NAME} v${APP_VERSION}..."

# 创建构建目录
mkdir -p "${DIST_DIR}"

# 打包为 FPK 文件（tar.gz 格式）
echo "📦 打包 FPK 文件..."
tar -czf "${DIST_DIR}/${APP_NAME}-${APP_VERSION}.fpk" \
    --exclude='*.fpk' \
    --exclude='dist' \
    --exclude='build.sh' \
    --exclude='.git' \
    -C "${BUILD_DIR}" .

echo "✅ 构建完成！"
echo "📁 输出文件: ${DIST_DIR}/${APP_NAME}-${APP_VERSION}.fpk"
echo ""
echo "📋 安装说明:"
echo "   1. 将 .fpk 文件上传到 fnOS NAS"
echo "   2. 在 fnOS 应用中心选择本地安装"
echo "   3. 选择上传的 .fpk 文件进行安装"
echo ""
echo "🌐 使用说明:"
echo "   安装完成后，在浏览器访问: http://$(hostname -I | awk '{print $1}'):8180"
