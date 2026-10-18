# Third-party notices

LASA's original source is under the repository [MIT license](LICENSE). Binary distributions include Go standard-library and third-party module code. Preserve the applicable notices and review exact license files when assembling a release.

| Component | License family / notice source |
| --- | --- |
| Go standard library | BSD-style license in the supported Go distribution |
| github.com/cilium/ebpf | MIT; see module LICENSE |
| github.com/spf13/cobra | Apache-2.0; see module LICENSE.txt |
| github.com/spf13/pflag | BSD-3-Clause; see module LICENSE |
| golang.org/x/sys | BSD-3-Clause; see module LICENSE and PATENTS where applicable |
| gopkg.in/yaml.v3 | MIT and Apache-2.0 notices; see module LICENSE and NOTICE |
| libbpf BPF helper headers used for compilation | See libbpf header SPDX identifiers and license notices; build dependency, not a userspace shared library link |

The embedded BPF program declares `Dual MIT/GPL` to the kernel and its LASA source is MIT. Module checksums and SBOMs inventory exact versions; this table does not assert that transitive license review or a legal compliance audit has been completed. Release tooling should bundle the exact applicable license/notice texts, not only this summary.

## Documentation website

The optional customer website uses the Python dependencies pinned in `requirements-docs.txt`; these are build tools, not scanner runtime dependencies. Exact MkDocs, Material, Mike and Material icon license texts for the pinned website version are retained in `docs/website/assets/licenses/NOTICE.txt` and copied into the published site. Retain upstream license comments in the generated theme JavaScript/CSS as well. Review and refresh these notices when upgrading the theme or its bundled assets.
