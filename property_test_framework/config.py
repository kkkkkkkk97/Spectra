"""
Configuration loader for TLS property testing framework
"""

import yaml
from pathlib import Path
from typing import Dict, Any, List


class TestConfig:
    """Load and manage testing configuration from YAML file"""

    def __init__(self, config_path: str = 'config.yaml'):
        """
        Initialize configuration loader

        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = Path(config_path)
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(self.config_path) as f:
            self.config = yaml.safe_load(f)

        # Merge Docker and local implementations
        self._merge_implementations()

    def _merge_implementations(self):
        """
        Merge Docker and local implementations into a unified dictionary

        This allows seamless handling of both Docker-based and local script-based
        TLS implementations in the test framework.
        """
        all_impls = {}

        # Load Docker implementations (existing)
        for name, cfg in self.config.get('implementations', {}).items():
            cfg.setdefault('target_type', 'docker')
            all_impls[name] = cfg

        # Load local implementations (new)
        for name, cfg in self.config.get('local_implementations', {}).items():
            cfg.setdefault('target_type', 'local')
            all_impls[name] = cfg

        self.all_implementations = all_impls

    def get_implementation(self, name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific TLS implementation (Docker or local)

        Args:
            name: Implementation name (e.g., 'openssl', 'openssl-3.4.0-local')

        Returns:
            Dictionary with implementation configuration

        Raises:
            ValueError: If implementation not found or disabled
        """
        impl = self.all_implementations.get(name)
        if not impl:
            raise ValueError(f"Implementation '{name}' not found in configuration")
        if not impl.get('enabled', True):
            raise ValueError(f"Implementation '{name}' is disabled")
        return impl

    def list_implementations(self, enabled_only: bool = True, target_type: str = None) -> List[str]:
        """
        List all available implementations

        Args:
            enabled_only: If True, only return enabled implementations
            target_type: Filter by type ('docker', 'local', or None for all)

        Returns:
            List of implementation names
        """
        impls = []
        for name, config in self.all_implementations.items():
            # Filter by enabled status
            if enabled_only and not config.get('enabled', True):
                continue

            # Filter by target type
            if target_type and config.get('target_type') != target_type:
                continue

            impls.append(name)

        return impls

    def get_client_certs(self, target_config=None) -> Dict[str, Path]:
        """
        Get client certificate paths for client-mode tests

        Args:
            target_config: Optional target configuration dict. If provided and has
                          'cert_dir', uses that directory instead of Docker certs.

        Returns:
            Dictionary with 'cert', 'key', 'ca' paths
        """
        # If target_config specifies cert_dir (e.g., manual mode), use it
        if target_config and 'cert_dir' in target_config:
            cert_dir = Path(target_config['cert_dir'])

            # WolfSSL uses *.pem naming in certs/ directory
            if 'certs' in str(cert_dir):
                return {
                    'cert': cert_dir / 'client-cert.pem',
                    'key': cert_dir / 'client-key.pem',
                    'ca': cert_dir / 'ca-cert.pem'
                }
            elif 'test' in str(cert_dir):
                return {
                    'cert': cert_dir / 'client.crt',
                    'key': cert_dir / 'client.key',
                    'ca': cert_dir / 'ca.crt'
                }
            # OpenSSL, mbedTLS, OpenHiTLS use *.cer/*.key naming
            else:
                return {
                    'cert': cert_dir / 'client.cer',
                    'key': cert_dir / 'declient.key',
                    'ca': cert_dir / 'ca.cer'
                }

        # Default: Use Docker certificates
        cert_dir = Path(self.config['certificates']['docker_certs_dir'])
        client_certs = self.config['certificates']['client']

        return {
            'cert': cert_dir / client_certs['cert'],
            'key': cert_dir / client_certs['key'],
            'ca': cert_dir / client_certs['ca']
        }

    def get_server_certs(self, target_config=None) -> Dict[str, Path]:
        """
        Get server certificate paths for server-mode tests

        Args:
            target_config: Optional target configuration dict. If provided and has
                          'cert_dir', uses that directory instead of local certs.

        Returns:
            Dictionary with 'cert', 'key' paths
        """
        # If target_config specifies cert_dir (e.g., manual mode), use it
        if target_config and 'cert_dir' in target_config:
            cert_dir = Path(target_config['cert_dir'])

            # WolfSSL uses *.pem naming in certs/ directory
            if 'certs' in str(cert_dir):
                return {
                    'cert': cert_dir / 'server-cert.pem',
                    'key': cert_dir / 'server-key.pem'
                }
            elif 'test' in str(cert_dir):
                return {
                    'cert': cert_dir / 'server.crt',
                    'key': cert_dir / 'server.key',
                }
            # OpenSSL, mbedTLS, OpenHiTLS use *.cer/*.key naming
            else:
                return {
                    'cert': cert_dir / 'server.cer',
                    'key': cert_dir / 'deserver.key'
                }

        # Default: Use local certificates
        cert_dir = Path(self.config['certificates']['local_certs_dir'])
        server_certs = self.config['certificates']['server']

        return {
            'cert': cert_dir / server_certs['cert'],
            'key': cert_dir / server_certs['key']
        }

    def is_local_implementation(self, name: str) -> bool:
        """
        Check if an implementation is local (script-based) or Docker

        Args:
            name: Implementation name

        Returns:
            True if local implementation, False if Docker
        """
        impl = self.get_implementation(name)
        return impl.get('target_type') == 'local'

    def get_local_certs(self, impl_name: str) -> Dict[str, Path]:
        """
        Get certificate paths for a local implementation

        Different TLS implementations use different certificate naming conventions:
        - WolfSSL: *.pem files in certs/ directory
        - Others: *.cer/*.key files in key/ or hi_key/ directory

        Args:
            impl_name: Local implementation name

        Returns:
            Dictionary with 'cert', 'key', 'ca' paths
        """
        impl = self.get_implementation(impl_name)

        if impl.get('target_type') != 'local':
            raise ValueError(f"Implementation '{impl_name}' is not a local implementation")

        cert_dir = Path(impl['cert_dir'])

        # WolfSSL uses *.pem naming in certs/ directory
        if 'certs' in str(cert_dir):
            return {
                'cert': cert_dir / 'client-cert.pem',
                'key': cert_dir / 'client-key.pem',
                'ca': cert_dir / 'ca-cert.pem'
            }
        elif 'test' in str(cert_dir):
            return {
                'cert': cert_dir / 'client.crt',
                'key': cert_dir / 'client.key',
                'ca': cert_dir / 'ca.crt'
            }
        # OpenSSL, mbedTLS, OpenHiTLS use *.cer/*.key naming
        else:
            return {
                'cert': cert_dir / 'client.cer',
                'key': cert_dir / 'declient.key',
                'ca': cert_dir / 'ca.cer'
            }

    def get_tls_settings(self) -> Dict[str, Any]:
        """Get TLS protocol settings"""
        return self.config['tls']

    def get_test_execution_settings(self) -> Dict[str, Any]:
        """Get test execution settings"""
        return self.config['test_execution']

    def get_property_metadata(self, property_id: str, mode: str) -> Dict[str, Any]:
        """
        Get metadata for a specific property

        Args:
            property_id: Property identifier (e.g., 'C1')
            mode: Test mode ('client' or 'server')

        Returns:
            Dictionary with property metadata
        """
        test_type = f"{mode}_tests"
        props = self.config['properties'].get(test_type, {})
        return props.get(property_id, {})

    def get_all_properties(self, mode: str) -> List[str]:
        """
        Get all property IDs for a specific mode

        Args:
            mode: Test mode ('client' or 'server')

        Returns:
            List of property IDs
        """
        test_type = f"{mode}_tests"
        props = self.config['properties'].get(test_type, {})
        return list(props.keys())

    def get_reporting_settings(self) -> Dict[str, Any]:
        """Get reporting settings"""
        return self.config['reporting']
