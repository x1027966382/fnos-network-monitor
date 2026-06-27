#!/usr/bin/env python3
"""
FnOS Network Monitor - 类似 RustNet 的网络监控工具
提供实时网络连接监控、进程网络使用追踪、深度包检测等功能
"""

import os
import sys
import json
import time
import signal
import threading
import subprocess
import socket
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('fnos-network-monitor')


class NetworkMonitor:
    """网络监控核心类"""

    def __init__(self, interface=None, port=8180):
        self.interface = interface
        self.port = port
        self.running = False
        self.connections = {}  # pid -> {connections: [], bytes_sent: 0, bytes_recv: 0}
        self.process_stats = {}  # pid -> {name, cmdline, ...}
        self.connections_history = deque(maxlen=1000)
        self.lock = threading.Lock()
        
        # 统计信息
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'total_bytes_sent': 0,
            'total_bytes_recv': 0,
            'protocols': defaultdict(int),
            'processes': defaultdict(int)
        }
        
        # 深度包检测结果
        self.packet_inspection = {}
        
        # 启动监控线程
        self.monitor_thread = None
        self.stats_thread = None

    def start(self):
        """启动监控"""
        self.running = True
        
        # 启动连接监控线程
        self.monitor_thread = threading.Thread(target=self._monitor_connections, daemon=True)
        self.monitor_thread.start()
        
        # 启动统计更新线程
        self.stats_thread = threading.Thread(target=self._update_stats, daemon=True)
        self.stats_thread.start()
        
        logger.info(f"Network monitor started on port {self.port}")

    def stop(self):
        """停止监控"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        if self.stats_thread:
            self.stats_thread.join(timeout=5)
        logger.info("Network monitor stopped")

    def _monitor_connections(self):
        """监控网络连接"""
        while self.running:
            try:
                # 获取所有网络连接
                connections = self._get_connections()
                
                with self.lock:
                    # 更新连接信息
                    for conn in connections:
                        pid = conn['pid']
                        if pid not in self.connections:
                            self.connections[pid] = {
                                'connections': [],
                                'bytes_sent': 0,
                                'bytes_recv': 0,
                                'last_update': time.time()
                            }
                        
                        # 更新连接列表
                        self.connections[pid]['connections'].append(conn)
                        self.connections[pid]['last_update'] = time.time()
                        
                        # 更新协议统计
                        protocol = conn.get('protocol', 'unknown')
                        self.stats['protocols'][protocol] += 1
                        
                        # 更新进程统计
                        if pid in self.process_stats:
                            process_name = self.process_stats[pid].get('name', f'PID-{pid}')
                            self.stats['processes'][process_name] += 1
                    
                    # 记录历史
                    self.connections_history.append({
                        'timestamp': time.time(),
                        'connections': connections
                    })
                
                time.sleep(1)  # 每秒更新一次
                
            except Exception as e:
                logger.error(f"Error monitoring connections: {e}")
                time.sleep(5)

    def _get_connections(self):
        """获取网络连接（简化实现）"""
        connections = []
        
        # 使用 /proc/net/tcp 和 /proc/net/udp 获取连接信息
        try:
            # TCP connections
            with open('/proc/net/tcp', 'r') as f:
                for line in f.readlines()[1:]:  # 跳过标题行
                    parts = line.split()
                    if len(parts) >= 10:
                        local_addr = self._parse_address(parts[1])
                        remote_addr = self._parse_address(parts[2])
                        state = int(parts[3], 16)
                        inode = int(parts[9])
                        
                        # 找到对应的进程
                        pid = self._find_pid_by_inode(inode)
                        
                        connections.append({
                            'local_address': local_addr,
                            'remote_address': remote_addr,
                            'state': self._tcp_state_name(state),
                            'pid': pid,
                            'protocol': 'tcp',
                            'inode': inode
                        })
            
            # UDP connections
            with open('/proc/net/udp', 'r') as f:
                for line in f.readlines()[1:]:  # 跳过标题行
                    parts = line.split()
                    if len(parts) >= 10:
                        local_addr = self._parse_address(parts[1])
                        remote_addr = self._parse_address(parts[2])
                        inode = int(parts[9])
                        
                        # 找到对应的进程
                        pid = self._find_pid_by_inode(inode)
                        
                        connections.append({
                            'local_address': local_addr,
                            'remote_address': remote_addr,
                            'state': 'UNCONN',
                            'pid': pid,
                            'protocol': 'udp',
                            'inode': inode
                        })
                        
        except Exception as e:
            logger.error(f"Error reading /proc/net: {e}")
        
        return connections

    def _parse_address(self, addr_str):
        """解析网络地址"""
        try:
            ip_hex, port_hex = addr_str.split(':')
            port = int(port_hex, 16)
            
            # 转换IP地址
            ip_int = int(ip_hex, 16)
            ip_bytes = ip_int.to_bytes(4, byteorder='little')
            ip = socket.inet_ntoa(ip_bytes)
            
            return f"{ip}:{port}"
        except:
            return addr_str

    def _find_pid_by_inode(self, inode):
        """通过inode查找进程PID"""
        try:
            # 遍历所有进程
            for pid_dir in Path('/proc').iterdir():
                if pid_dir.name.isdigit():
                    fd_dir = pid_dir / 'fd'
                    if fd_dir.exists():
                        for fd in fd_dir.iterdir():
                            try:
                                link = fd.readlink()
                                if f'socket:[{inode}]' in link:
                                    return int(pid_dir.name)
                            except:
                                continue
        except:
            pass
        return -1

    def _tcp_state_name(self, state):
        """获取TCP状态名称"""
        states = {
            1: 'ESTABLISHED',
            2: 'SYN_SENT',
            3: 'SYN_RECV',
            4: 'FIN_WAIT1',
            5: 'FIN_WAIT2',
            6: 'TIME_WAIT',
            7: 'CLOSE',
            8: 'CLOSE_WAIT',
            9: 'LAST_ACK',
            10: 'LISTEN',
            11: 'CLOSING'
        }
        return states.get(state, f'UNKNOWN({state})')

    def _update_stats(self):
        """更新统计信息"""
        while self.running:
            try:
                # 更新进程信息
                self._update_process_info()
                
                # 更新连接统计
                with self.lock:
                    self.stats['active_connections'] = sum(
                        len(conn['connections']) for conn in self.connections.values()
                    )
                
                time.sleep(5)  # 每5秒更新一次统计
                
            except Exception as e:
                logger.error(f"Error updating stats: {e}")
                time.sleep(10)

    def _update_process_info(self):
        """更新进程信息"""
        try:
            # 获取所有进程信息
            for pid_dir in Path('/proc').iterdir():
                if pid_dir.name.isdigit():
                    pid = int(pid_dir.name)
                    
                    # 读取进程状态
                    status_file = pid_dir / 'status'
                    if status_file.exists():
                        with open(status_file, 'r') as f:
                            status = f.read()
                            
                        # 提取进程名和命令行
                        name = self._extract_field(status, 'Name')
                        cmdline = self._extract_cmdline(pid_dir)
                        
                        if pid not in self.process_stats:
                            self.process_stats[pid] = {
                                'name': name,
                                'cmdline': cmdline,
                                'first_seen': time.time()
                            }
                        
                        # 更新时间戳
                        self.process_stats[pid]['last_seen'] = time.time()
            
            # 清理过期进程
            current_time = time.time()
            expired_pids = [
                pid for pid, info in self.process_stats.items()
                if current_time - info.get('last_seen', 0) > 300  # 5分钟过期
            ]
            
            for pid in expired_pids:
                del self.process_stats[pid]
                
        except Exception as e:
            logger.error(f"Error updating process info: {e}")

    def _extract_field(self, status, field):
        """从状态文件中提取字段"""
        for line in status.split('\n'):
            if line.startswith(f'{field}:'):
                return line.split(':', 1)[1].strip()
        return 'unknown'

    def _extract_cmdline(self, pid_dir):
        """提取进程命令行"""
        try:
            cmdline_file = pid_dir / 'cmdline'
            if cmdline_file.exists():
                with open(cmdline_file, 'r') as f:
                    cmdline = f.read().replace('\x00', ' ')
                    return cmdline.strip()
        except:
            pass
        return ''

    def get_connections(self, pid=None):
        """获取连接信息"""
        with self.lock:
            if pid:
                return self.connections.get(pid, {}).get('connections', [])
            
            all_connections = []
            for pid, conn_info in self.connections.items():
                all_connections.extend(conn_info['connections'])
            return all_connections

    def get_process_stats(self):
        """获取进程统计"""
        with self.lock:
            stats = []
            for pid, conn_info in self.connections.items():
                if pid in self.process_stats:
                    process_info = self.process_stats[pid]
                    stats.append({
                        'pid': pid,
                        'name': process_info.get('name', f'PID-{pid}'),
                        'cmdline': process_info.get('cmdline', ''),
                        'connections': len(conn_info.get('connections', [])),
                        'bytes_sent': conn_info.get('bytes_sent', 0),
                        'bytes_recv': conn_info.get('bytes_recv', 0)
                    })
            return stats

    def get_global_stats(self):
        """获取全局统计"""
        with self.lock:
            return {
                'active_connections': self.stats['active_connections'],
                'protocols': dict(self.stats['protocols']),
                'processes': dict(self.stats['processes']),
                'uptime': time.time() - self.start_time if hasattr(self, 'start_time') else 0
            }

    def deep_inspect(self, pid=None, max_packets=100):
        """深度包检测"""
        # 这里可以集成更复杂的包检测逻辑
        # 简化实现：返回基本的连接信息
        results = []
        
        connections = self.get_connections(pid)
        for conn in connections[:max_packets]:
            result = {
                'local': conn.get('local_address', ''),
                'remote': conn.get('remote_address', ''),
                'protocol': conn.get('protocol', ''),
                'state': conn.get('state', ''),
                'process': self.process_stats.get(conn.get('pid', -1), {}).get('name', 'unknown')
            }
            results.append(result)
        
        return results


def create_app():
    """创建Flask应用"""
    from flask import Flask, jsonify, request, render_template
    
    app = Flask(__name__, 
                template_folder='/opt/fnos-rustnet/app/ui/templates',
                static_folder='/opt/fnos-rustnet/app/ui/static')
    
    monitor = NetworkMonitor()
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/api/connections')
    def get_connections():
        pid = request.args.get('pid', type=int)
        connections = monitor.get_connections(pid)
        return jsonify(connections)
    
    @app.route('/api/processes')
    def get_processes():
        processes = monitor.get_process_stats()
        return jsonify(processes)
    
    @app.route('/api/stats')
    def get_stats():
        stats = monitor.get_global_stats()
        return jsonify(stats)
    
    @app.route('/api/inspect')
    def inspect():
        pid = request.args.get('pid', type=int)
        max_packets = request.args.get('max_packets', 100, type=int)
        results = monitor.deep_inspect(pid, max_packets)
        return jsonify(results)
    
    return app, monitor


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='FnOS Network Monitor')
    parser.add_argument('--port', type=int, default=8180, help='Web interface port')
    parser.add_argument('--interface', type=str, help='Network interface to monitor')
    args = parser.parse_args()
    
    # 创建应用
    app, monitor = create_app()
    monitor.port = args.port
    monitor.interface = args.interface
    monitor.start_time = time.time()
    
    # 信号处理
    def signal_handler(sig, frame):
        logger.info("Received shutdown signal")
        monitor.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # 启动监控
        monitor.start()
        
        # 启动Web服务器
        logger.info(f"Starting web server on port {args.port}")
        app.run(host='0.0.0.0', port=args.port, debug=False)
        
    except KeyboardInterrupt:
        monitor.stop()
    except Exception as e:
        logger.error(f"Application error: {e}")
        monitor.stop()
        sys.exit(1)


if __name__ == '__main__':
    main()
