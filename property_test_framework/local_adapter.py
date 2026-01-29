"""
Local TLS Implementation Adapter
管理本地TLS实现脚本的生命周期 (启动/停止/健康检查)

作者: Claude Code
日期: 2026-01-05
"""

import os
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict


class LocalServerAdapter:
    """
    本地TLS服务器/客户端脚本适配器

    用于管理shell脚本启动的TLS实现，提供:
    - 服务器启动/停止 (./script.sh -s [0|1])
    - 客户端启动 (./script.sh -c)
    - 端口就绪检测
    - 优雅终止和强制清理
    """

    def __init__(self, config: Dict):
        """
        初始化适配器

        Args:
            config: 实现配置字典，包含:
                - script_path: 脚本路径
                - port: 监听端口
                - host: 主机地址 (默认 127.0.0.1)
                - name: 实现名称 (用于日志)
        """
        self.config = config
        self.script_path = Path(config['script_path'])
        self.port = config.get('port', 4433)
        self.host = config.get('host', '127.0.0.1')
        self.name = config.get('name', 'Unknown')
        self.version = config.get('version', '')

        self.process: Optional[subprocess.Popen] = None
        self._pgid: Optional[int] = None  # Process group ID

        # 验证脚本存在
        if not self.script_path.exists():
            raise FileNotFoundError(f"Script not found: {self.script_path}")

        if not os.access(self.script_path, os.X_OK):
            raise PermissionError(f"Script not executable: {self.script_path}")

    def start_server(self, verify_client: bool = False, timeout: int = 10) -> bool:
        """
        启动TLS服务器

        Args:
            verify_client: 是否要求客户端证书 (True: -s 1, False: -s 0)
            timeout: 等待服务器就绪的超时时间（秒）

        Returns:
            bool: 启动成功并就绪返回True

        Raises:
            RuntimeError: 服务器启动失败或进程立即退出
        """
        verify_flag = "1" if verify_client else "0"
        cmd = [str(self.script_path), '-s', verify_flag]

        print(f"[LocalAdapter] Starting {self.name} {self.version} server...")
        print(f"[LocalAdapter] Command: {' '.join(cmd)}")

        try:
            # 创建独立进程组，方便统一清理
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,  # Create new process group
                cwd=self.script_path.parent
            )

            # 保存进程组ID
            self._pgid = os.getpgid(self.process.pid)

            # 短暂等待，检查进程是否立即退出
            time.sleep(0.5)
            if self.process.poll() is not None:
                # 进程已退出，读取错误输出
                _, stderr = self.process.communicate()
                raise RuntimeError(
                    f"Server process exited immediately with code {self.process.returncode}\n"
                    f"stderr: {stderr.decode('utf-8', errors='ignore')}"
                )

            # 等待端口就绪
            if not self.is_ready(timeout=timeout):
                self.stop()  # 清理进程
                raise RuntimeError(
                    f"Server did not become ready on port {self.port} within {timeout}s"
                )

            print(f"[LocalAdapter] Server ready on {self.host}:{self.port}")
            return True

        except Exception as e:
            # 确保清理进程
            if self.process:
                self.stop()
            raise RuntimeError(f"Failed to start server: {e}") from e

    def start_client(self) -> subprocess.Popen:
        """
        启动TLS客户端（非阻塞）

        Returns:
            subprocess.Popen: 客户端进程句柄

        Note:
            调用者负责管理返回的进程生命周期
        """
        cmd = [str(self.script_path), '-c']

        print(f"[LocalAdapter] Starting {self.name} {self.version} client...")
        print(f"[LocalAdapter] Command: {' '.join(cmd)}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                cwd=self.script_path.parent
            )

            print(f"[LocalAdapter] Client started (PID: {process.pid})")
            return process

        except Exception as e:
            raise RuntimeError(f"Failed to start client: {e}") from e

    def is_ready(self, timeout: int = 10) -> bool:
        """
        检查服务器是否就绪（端口可连接）

        Args:
            timeout: 超时时间（秒）

        Returns:
            bool: 服务器就绪返回True，超时返回False
        """
        start_time = time.time()
        retry_interval = 0.5

        while time.time() - start_time < timeout:
            try:
                # 尝试连接端口
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                sock.connect((self.host, self.port))
                sock.close()

                # 连接成功，服务器就绪
                return True

            except (socket.error, ConnectionRefusedError, OSError):
                # 连接失败，继续重试
                time.sleep(retry_interval)

            # 检查进程是否已退出
            if self.process and self.process.poll() is not None:
                print(f"[LocalAdapter] Server process exited unexpectedly")
                return False

        # 超时
        print(f"[LocalAdapter] Timeout waiting for port {self.port}")
        return False

    def stop(self, timeout: int = 5):
        """
        停止服务器/客户端进程

        Args:
            timeout: 等待优雅终止的超时时间（秒）

        Note:
            先发送SIGTERM尝试优雅终止，超时后发送SIGKILL强制终止
        """
        if not self.process:
            return

        try:
            # 检查进程是否已经退出
            if self.process.poll() is not None:
                print(f"[LocalAdapter] Process already exited")
                return

            print(f"[LocalAdapter] Stopping process (PID: {self.process.pid})...")

            # 尝试优雅终止（SIGTERM）
            if self._pgid:
                try:
                    os.killpg(self._pgid, signal.SIGTERM)
                except ProcessLookupError:
                    # 进程组不存在，可能已退出
                    return
            else:
                self.process.terminate()

            # 等待进程退出
            try:
                self.process.wait(timeout=timeout)
                print(f"[LocalAdapter] Process terminated gracefully")
                return
            except subprocess.TimeoutExpired:
                print(f"[LocalAdapter] Process did not terminate, forcing kill...")

            # 强制终止（SIGKILL）
            if self._pgid:
                try:
                    os.killpg(self._pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                self.process.kill()

            # 等待确认退出
            self.process.wait(timeout=2)
            print(f"[LocalAdapter] Process killed")

        except Exception as e:
            print(f"[LocalAdapter] Error stopping process: {e}")

        finally:
            self.process = None
            self._pgid = None

    def __enter__(self):
        """上下文管理器：进入"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器：自动清理"""
        self.stop()
        return False  # 不抑制异常

    def __repr__(self):
        status = "running" if (self.process and self.process.poll() is None) else "stopped"
        return f"<LocalServerAdapter {self.name} {self.version} [{status}]>"


def ensure_port_available(port: int, host: str = '127.0.0.1', timeout: int = 5) -> bool:
    """
    确保端口可用（等待前一个测试释放端口）

    Args:
        port: 端口号
        host: 主机地址
        timeout: 超时时间（秒）

    Returns:
        bool: 端口可用返回True，超时返回False
    """
    start_time = time.time()
    retry_interval = 0.5

    while time.time() - start_time < timeout:
        try:
            # 尝试绑定端口
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.close()

            # 绑定成功，端口可用
            return True

        except OSError:
            # 端口被占用，继续等待
            time.sleep(retry_interval)

    # 超时
    print(f"[LocalAdapter] Port {port} still in use after {timeout}s")
    return False
