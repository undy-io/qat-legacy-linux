# Legacy Intel QAT driver for Linux

Community maintenance of Intel's **QAT.L.4.28.0-00004** release, including
kernel drivers, the CPA userspace library, the USDM DMA allocator, firmware,
configuration tools and samples. The initial work makes this release build
and operate on the tested Linux 7 host described below.

This is an independent community project. Intel's original documentation is
preserved in [README](README); the original copyright notices and licenses
remain in the source tree. The separate [qatgo](https://github.com/undy-io/qatgo)
repository provides Go DMA buffer pools and asynchronous SHA-256 hashing on
this stack.

## Provenance

The source baseline is Intel's unmodified `QAT.L.4.28.0-00004.tar.gz`, obtained
from the [Intel Customer Enabling release download](https://www.intel.com/content/www/us/en/download/19734/intel-quickassist-technology-intel-qat-driver-for-linux-for-customer-enabling-ce-release.html).
The archive's SHA-256 matches Intel's published checksum:

```text
0ac77429774c6571cff48cc6ddb0d1a44b2696612ddc89e9f5c563d0350eb716
```

The intended repository history keeps that release import as a pristine
baseline, with compatibility changes in separate commits. It does not recover
Intel's original development history.

## Validated configuration

| Component | Tested configuration |
| --- | --- |
| Operating system | Ubuntu 24.04, x86-64 |
| Kernel | `7.0.0-43-generic` |
| Compiler | GCC 13.3.0 |
| Accelerator | Intel QuickAssist Adapter 8970, C62x / QAT 1.x |
| Topology | Three physical endpoints on one card |
| Build mode | SR-IOV host; applications use local virtual functions |
| Runtime prefix | `/opt/qat` |

The card was exercised with local userspace applications, including streaming
SHA-256, concurrent instances across all three endpoints, DMA buffer reuse
and digest comparisons against CPU implementations. The
[Go module documentation](https://github.com/undy-io/qatgo) contains the
application-level tests and measured results.

The imported release contains support for additional device families and
older kernels. Their presence in the source is not a validation claim for
this community version. Changes to the Linux IOMMU path are guarded for
kernel 7 and later; other kernel versions still require their own build and
runtime checks.

## Compatibility changes

The initial changes affect six source/build files:

- Pass include paths and feature definitions through Kbuild's `ccflags-y`.
- Preserve object command files and symbol-version metadata when intermediate
  libraries are linked into `qat_api.ko`, including assembly members.
- Carry Kbuild flags into the functional kernel samples.
- Replace a trailing zero-length array with a flexible array in UIO control.
- Allocate the QDM IOMMU paging domain from a device on kernel 7, with locking
  around its first allocation and device attachment.

These changes belong in the checked-in sources. A separately saved patch is
not required to build a checkout.

## Build without installing

Build in a writable checkout. Install headers matching the kernel you intend
to run; `/lib/modules/$(uname -r)/build` must point to that kernel's prepared
build tree. A custom kernel may require headers from its provider rather than
Ubuntu's standard repositories. Use a compiler compatible with the one used
for the kernel.

For the tested Ubuntu configuration, build dependencies include:

```sh
sudo apt-get install build-essential pkg-config gawk pciutils nasm \
  libboost-dev libudev-dev libnl-3-dev libnl-genl-3-dev zlib1g-dev libssl-dev \
  linux-headers-"$(uname -r)"
```

This release's configure script checks for both libnl development packages in
non-Xen builds. Consult the original [README](README) for the release's other
dependency and feature details.

The configuration used on the validated host was:

```sh
./configure --prefix=/opt/qat --enable-icp-sriov=host
make
```

Optional sample build:

```sh
make samples
```

These commands compile the software without installing modules or restarting
devices. The release's build system cleans and rebuilds parts of the tree on
subsequent invocations; see the known issues in the original [README](README).
`./configure --help` lists the other build modes and options.

SR-IOV host mode is also suitable for applications running directly on the
host: VFs can remain bound to the local QAT VF driver. Passing VFs to virtual
machines is a separate deployment choice. Device configuration determines
which services and instances applications can open.

### Legacy hash opt-in

The tested build leaves legacy algorithms disabled, which is the release
default. SHA-1, MD5 and SHA-224 require `--enable-legacy-algorithms` in addition
to the selected configuration options. Changing that setting requires a
matching rebuild and deployment of the kernel modules and userspace
libraries, followed by capability and correctness checks. A device
configuration edit alone does not enable them. See Intel's
[algorithm support matrix](https://www.intel.com/content/www/us/en/support/articles/000093843/technologies/intel-quickassist-technology-intel-qat.html).

## Installation and operation

Plan installation separately from a build. The release's `make install`
target installs kernel modules, userspace libraries, firmware, device
configuration, udev rules and service files. It can replace existing QAT
configuration and start services. `make qat-conf-install` also moves existing
device configuration aside and regenerates it; preserve any custom settings
before using it.

Linux also supplies in-tree QAT drivers. Choose the intended stack and check
which modules are loaded and which files `modinfo` resolves before switching
drivers. Kernel modules and userspace libraries from different stacks or
builds must not be combined without validating their compatibility. Module
signing may be necessary when Secure Boot is enabled; the original
[README](README) documents `mod_sign_cmd`.

Stop and drain QAT applications before replacing modules, changing VF
bindings or restarting devices. DMA buffers must remain allocated until
hardware operations have actually completed. Installation, driver reloads,
service restarts and VF setup are explicit administrator actions; the build
instructions above do not perform them.

Use Intel's [Getting Started Guide](https://cdrdv2.intel.com/v1/dl/getContent/710059)
for deployment and configuration, and its
[Programmer's Guide](https://cdrdv2.intel.com/v1/dl/getContent/710060) for the CPA
API and application lifecycle. The service layout and number of instances
depend on the deployment; a second card requires configuration for its newly
discovered endpoints and VFs.

## Licensing

This release uses multiple licenses. Preserve the license header and notices
applicable to each file; there is no replacement project-wide license.

- [LICENSE.GPL](LICENSE.GPL), [LICENSE.BSD](LICENSE.BSD) and
  [LICENSE.APACHE](LICENSE.APACHE), together with source-file headers, cover
  the corresponding source components.
- [ThirdPartyLicenseIndex.txt](ThirdPartyLicenseIndex.txt) and
  [ThirdPartyNotice-openssl.txt](ThirdPartyNotice-openssl.txt) record bundled
  third-party material.
- Binary material is supplied under
  [binary-redistribution-license.txt](binary-redistribution-license.txt).
  Firmware also carries its
  [own license](quickassist/lookaside/firmware/license.txt); preserve those
  terms and notices when redistributing it.

When reporting a compatibility issue, include the release/commit, device PCI
IDs, distribution, complete kernel version, compiler version, configure
options and the relevant build or runtime error.
