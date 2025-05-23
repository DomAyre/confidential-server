package policy

import future.keywords.every
import future.keywords.in

api_version := "0.10.0"
framework_version := "0.2.3"

fragments := [
  {
    "feed": "mcr.microsoft.com/aci/aci-cc-infra-fragment",
    "includes": [
      "containers",
      "fragments"
    ],
    "issuer": "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.3",
    "minimum_svn": "1"
  }
]

containers := [
  {
    "allow_elevated": false,
    "allow_stdio_access": true,
    "capabilities": {
      "ambient": [],
      "bounding": [
        "CAP_AUDIT_WRITE",
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_MKNOD",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT"
      ],
      "effective": [
        "CAP_AUDIT_WRITE",
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_MKNOD",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT"
      ],
      "inheritable": [],
      "permitted": [
        "CAP_AUDIT_WRITE",
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_MKNOD",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT"
      ]
    },
    "command": [
      "/bin/bash",
      "-c",
      "join(createArray('get_snp_version &&', 'echo \"$(get_attestation_ccf)\" &&', 'get_attestation_ccf \"example-report-data\" | xargs -0', 'verify_attestation_ccf', '--report-data \"example-report-data\"', '--security-policy-b64 \"$(cat /src/policy_aci.rego | base64 -w 0)\"'), ' ')"
    ],
    "env_rules": [
      {
        "pattern": "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "required": false,
        "strategy": "string"
      },
      {
        "pattern": "TERM=xterm",
        "required": false,
        "strategy": "string"
      },
      {
        "pattern": "(?i)(FABRIC)_.+=.+",
        "required": false,
        "strategy": "re2"
      },
      {
        "pattern": "HOSTNAME=.+",
        "required": false,
        "strategy": "re2"
      },
      {
        "pattern": "T(E)?MP=.+",
        "required": false,
        "strategy": "re2"
      },
      {
        "pattern": "FabricPackageFileName=.+",
        "required": false,
        "strategy": "re2"
      },
      {
        "pattern": "HostedServiceName=.+",
        "required": false,
        "strategy": "re2"
      },
      {
        "pattern": "IDENTITY_API_VERSION=.+",
        "required": false,
        "strategy": "re2"
      },
      {
        "pattern": "IDENTITY_HEADER=.+",
        "required": false,
        "strategy": "re2"
      },
      {
        "pattern": "IDENTITY_SERVER_THUMBPRINT=.+",
        "required": false,
        "strategy": "re2"
      },
      {
        "pattern": "azurecontainerinstance_restarted_by=.+",
        "required": false,
        "strategy": "re2"
      }
    ],
    "exec_processes": [],
    "id": "ghcr.io/domayre/confidential-server/attestation:latest",
    "layers": [
      "b4cfd4459bbd0d6368ce26c1fb6d90fdf405a1154ed42771cdd4e674befc1875",
      "2d7240b9011c07999c15eb003e3c8f6ce56059900e48743ab789b64be2057a24",
      "d2c21b94d4505c0750e8ea59ab27a72d15502cd15e1d58f809cad204e43fa040",
      "8381e5a731a67a49e16941cb51512ab60e3c6b1a76281e0e760e5b30557fe704"
    ],
    "mounts": [
      {
        "destination": "/etc/resolv.conf",
        "options": [
          "rbind",
          "rshared",
          "rw"
        ],
        "source": "sandbox:///tmp/atlas/resolvconf/.+",
        "type": "bind"
      }
    ],
    "name": "attestation",
    "no_new_privileges": false,
    "seccomp_profile_sha256": "",
    "signals": [],
    "user": {
      "group_idnames": [
        {
          "pattern": "",
          "strategy": "any"
        }
      ],
      "umask": "0022",
      "user_idname": {
        "pattern": "",
        "strategy": "any"
      }
    },
    "working_dir": "/"
  },
  {
    "allow_elevated": false,
    "allow_stdio_access": true,
    "capabilities": {
      "ambient": [],
      "bounding": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ],
      "effective": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ],
      "inheritable": [],
      "permitted": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETFCAP",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_SYS_CHROOT",
        "CAP_KILL",
        "CAP_AUDIT_WRITE"
      ]
    },
    "command": [
      "/pause"
    ],
    "env_rules": [
      {
        "pattern": "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "required": true,
        "strategy": "string"
      },
      {
        "pattern": "TERM=xterm",
        "required": false,
        "strategy": "string"
      }
    ],
    "exec_processes": [],
    "layers": [
      "16b514057a06ad665f92c02863aca074fd5976c755d26bff16365299169e8415"
    ],
    "mounts": [],
    "name": "pause-container",
    "no_new_privileges": false,
    "seccomp_profile_sha256": "",
    "signals": [],
    "user": {
      "group_idnames": [
        {
          "pattern": "",
          "strategy": "any"
        }
      ],
      "umask": "0022",
      "user_idname": {
        "pattern": "",
        "strategy": "any"
      }
    },
    "working_dir": "/"
  }
]

allow_properties_access := true
allow_dump_stacks := false
allow_runtime_logging := false
allow_environment_variable_dropping := true
allow_unencrypted_scratch := false
allow_capability_dropping := true

mount_device := data.framework.mount_device
unmount_device := data.framework.unmount_device
mount_overlay := data.framework.mount_overlay
unmount_overlay := data.framework.unmount_overlay
create_container := data.framework.create_container
exec_in_container := data.framework.exec_in_container
exec_external := data.framework.exec_external
shutdown_container := data.framework.shutdown_container
signal_container_process := data.framework.signal_container_process
plan9_mount := data.framework.plan9_mount
plan9_unmount := data.framework.plan9_unmount
get_properties := data.framework.get_properties
dump_stacks := data.framework.dump_stacks
runtime_logging := data.framework.runtime_logging
load_fragment := data.framework.load_fragment
scratch_mount := data.framework.scratch_mount
scratch_unmount := data.framework.scratch_unmount

reason := {"errors": data.framework.errors}


