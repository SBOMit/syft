# syft (fork)
This repository is a fork of the upstream `syft` project (https://github.com/anchore/syft).
For full documentation and advanced options, see the upstream project.

## How to build and run

#### Prerequisites

- Go 1.20+ installed and on your PATH

#### Build
From the repository root:
```bash
make build
```

#### Run
Replace `location-to-your-binary` with the directory where `make build` produced the `syft` binary, then run:

```bash
location-to-your-binary/syft -v scan dir:{projectdir} \
  --output {output-format} \
  --attestation {attestation-file} \
  --attestation-type "command-run"
```