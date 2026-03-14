# Fuzz Testing for mtr

This directory contains [libFuzzer](https://llvm.org/docs/LibFuzzer.html) fuzz targets for [mtr](https://github.com/traviscross/mtr), a network diagnostic tool that combines `traceroute` and `ping`.

---

## Fuzz Targets

| File | What it fuzzes |
|------|----------------|
| `fuzz_handle_received_ip4_packet.c` | IPv4 packet parsing — finds crashes in the IPv4 receive path |
| `fuzz_handle_received_ip6_packet.c` | IPv6 packet parsing — finds crashes in the IPv6 receive path |
| `fuzz_handle_error_queue_packet.c` | ICMP error queue packet handling |
| `fuzz_parse_command.c` | Text command parser — tokenises commands from stdin/IPC |

---

## Seed Corpus

The `corpus/` directory contains hand-crafted seed inputs covering:

- Valid minimal IPv4/IPv6 packets
- Valid ICMP echo reply / TTL-exceeded messages
- MPLS label stack extensions
- Edge cases: maximum IHL, zero-length payloads, all-zeros packets
- Malformed inputs: truncated headers, wrong version fields, bad checksums
- Text command seeds for the command parser

---

## What is OSS-Fuzz?

[OSS-Fuzz](https://github.com/google/oss-fuzz) is Google's free, continuous fuzzing service for critical open-source projects. It runs fuzz targets 24 / 7 at scale using:

- **Coverage-guided mutation** — libFuzzer, AFL++, Honggfuzz
- **Sanitizers** — AddressSanitizer (memory errors), UBSan (undefined behaviour), MemorySanitizer
- **Automatic crash deduplication** and bug reporting to maintainers

OSS-Fuzz has found [thousands of bugs](https://bugs.chromium.org/p/oss-fuzz/issues/list) in critical open-source projects. Once integrated, bugs are reported privately and automatically.

---

## Running Locally

### Prerequisites

- Docker
- The [OSS-Fuzz repository](https://github.com/google/oss-fuzz) checked out locally

### Build the fuzz targets

```bash
# From your local oss-fuzz checkout:
python infra/helper.py build_image mtr
python infra/helper.py build_fuzzers mtr
```

Or directly with Docker using the files in this directory:

```bash
# Build the image
docker build -t mtr-fuzz .

# Compile (outputs to /tmp/out on host)
mkdir -p /tmp/mtr-out
docker run --rm \
  -v /tmp/mtr-out:/out \
  -e FUZZING_ENGINE=libfuzzer \
  -e SANITIZER=address \
  -e ARCHITECTURE=x86_64 \
  -e OUT=/out \
  -e LIB_FUZZING_ENGINE=/usr/lib/libFuzzingEngine.a \
  mtr-fuzz \
  /usr/local/bin/compile
```

### Run a fuzz target

```bash
# Smoke test (5 seconds) inside base-runner
docker run --rm \
  -v /tmp/mtr-out:/out:ro \
  gcr.io/oss-fuzz-base/base-runner \
  bash -c '/out/fuzz_handle_received_ip4_packet /out/corpus -max_total_time=5'
```

### Run with your own corpus

```bash
# Create a corpus directory and run indefinitely
mkdir -p /tmp/my-corpus
docker run --rm \
  -v /tmp/mtr-out:/out:ro \
  -v /tmp/my-corpus:/corpus \
  gcr.io/oss-fuzz-base/base-runner \
  bash -c '/out/fuzz_handle_received_ip4_packet /corpus /out/corpus'
```

libFuzzer will print coverage statistics as it runs. Press `Ctrl-C` to stop. Any crashes are written to the current directory as `crash-<hash>`.

### Reproduce a crash

```bash
docker run --rm \
  -v /tmp/mtr-out:/out:ro \
  -v /path/to/crash:/crash \
  gcr.io/oss-fuzz-base/base-runner \
  bash -c '/out/fuzz_handle_received_ip4_packet /crash/crash-<hash>'
```

---

## Files

```
fuzz/
├── fuzz_handle_received_ip4_packet.c
├── fuzz_handle_received_ip6_packet.c
├── fuzz_handle_error_queue_packet.c
├── fuzz_parse_command.c
├── corpus/                        seed inputs (binary + text)
└── README.md                      this file
```

The OSS-Fuzz integration files (`project.yaml`, `Dockerfile`, `build.sh`) live in the [OSS-Fuzz repository](https://github.com/google/oss-fuzz/tree/master/projects/mtr).