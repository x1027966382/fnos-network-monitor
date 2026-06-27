# FnOS Network Monitor

基于 RustNet 理念设计的网络监控工具，专为飞牛 NAS (fnOS) 设计。

## 功能特性

- 🔍 **实时网络连接监控** - 监控所有 TCP/UDP 连接
- 📊 **进程网络使用追踪** - 按进程统计网络使用情况
- 🔗 **深度包检测** - 识别 HTTP、TLS、DNS、SSH 等协议
- 🌐 **Web 界面** - 通过浏览器访问的现代化界面
- ⚡ **低资源占用** - 轻量级设计，不影响 NAS 性能

## 安装方法

### 方法一：FPK 安装包安装（推荐）

1. 下载最新的 `.fpk` 文件
2. 在 fnOS 应用中心选择"本地安装"
3. 选择下载的 `.fpk` 文件进行安装

### 方法二：手动构建

```bash
# 克隆仓库
git clone <repository-url>
cd fnos-network-monitor

# 构建 FPK 安装包
chmod +x build.sh
./build.sh
```

## 使用说明

安装完成后，在浏览器访问：
```
http://<NAS_IP>:8180
```

### Web 界面功能

- **网络连接面板**：显示所有活跃网络连接
- **进程监控面板**：按进程统计网络使用
- **实时统计**：连接数、协议分布等
- **筛选功能**：按协议、进程名、IP 地址筛选

## API 接口

### 获取连接信息
```
GET /api/connections
GET /api/connections?pid=<PID>
```

### 获取进程统计
```
GET /api/processes
```

### 获取全局统计
```
GET /api/stats
```

### 深度包检测
```
GET /api/inspect?pid=<PID>&max_packets=100
```

## 技术栈

- **后端**：Python 3 + Flask
- **前端**：HTML5 + CSS3 + JavaScript
- **数据源**：/proc/net/tcp, /proc/net/udp
- **进程追踪**：/proc 文件系统

## 权限要求

本应用需要 root 权限以访问 `/proc` 文件系统获取网络连接信息。

## 目录结构

```
fnos-network-monitor/
├── manifest              # 应用元信息
├── config/
│   ├── privilege         # 权限配置
│   └── resource          # 资源类型
├── cmd/
│   └── main              # 生命周期脚本
├── app/
│   ├── app/
│   │   ├── network_monitor.py  # 主程序
│   │   └── requirements.txt    # Python 依赖
│   └── ui/
│       ├── config              # Web 界面配置
│       └── templates/
│           └── index.html      # Web 界面
├── build.sh              # 构建脚本
└── README.md             # 说明文档
```

## 许可证

MIT License

## 致谢

- [RustNet](https://github.com/domcyrus/rustnet) - 项目灵感来源
- [fnOS](https://www.fnnas.com/) - 飞牛 NAS 操作系统
