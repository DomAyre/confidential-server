

import os
import yaml
import re
from dataclasses import dataclass
from typing import Dict, List, Union


@dataclass
class ServerTargetConfig:
    path: str
    policies: Union[str, List[str]]

    def _validate_path(self):
        if not isinstance(self.path, str):
            raise ValueError("Path must be a string.")
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"Path '{self.path}' does not exist.")
        if not os.access(self.path, os.R_OK):
            raise PermissionError(f"Path '{self.path}' is not readable.")

    def _validate_policies(self):
        if isinstance(self.policies, list):
            if not all(isinstance(item, str) for item in self.policies):
                raise ValueError("Each policy in the list must be a string.")
        elif not isinstance(self.policies, str):
            raise ValueError("Policies must be either a string or a list of strings.")

    def __post_init__(self):
        self._validate_path()
        self._validate_policies()


@dataclass
class ServerConfig:
    serve: List[ServerTargetConfig]
    security_policies: Dict[str, str]

    def _validate_target_configs(self):
        if not isinstance(self.serve, list):
            raise ValueError("Serve must be a list of ServerTargetConfig.")
        for target in self.serve:
            if not isinstance(target, ServerTargetConfig):
                raise ValueError("Each item in serve must be a ServerTargetConfig instance.")
            if isinstance(target.policies, str):
                if target.policies not in self.security_policies:
                    raise ValueError(f"Policy '{target.policies}' not found in security policies.")
            elif isinstance(target.policies, list):
                for policy in target.policies:
                    if policy not in self.security_policies:
                        raise ValueError(f"Policy '{policy}' not found in security policies.")

    def _validate_security_policies(self):
        for key, value in self.security_policies.items():
            if not isinstance(value, str):
                raise ValueError(f"Security policy for '{key}' must be a string.")
            if not re.compile(r'^[A-Za-z0-9+/]+={0,2}$').fullmatch(value):
                raise ValueError(f"The security policy value for '{key}' does not match the required pattern.")

    def __post_init__(self):
        self.serve = [ServerTargetConfig(**target) for target in self.serve]
        self._validate_target_configs()
        self._validate_security_policies()


def parse_config_file(config_path):
    if os.path.isfile(config_path):
        with open(config_path) as f:
            return ServerConfig(**yaml.safe_load(f))