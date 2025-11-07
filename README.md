![mipsmatch](https://raw.githubusercontent.com/ttkb-oss/mipsmatch/refs/heads/master/doc/images/mipsmatch-logo%400.5x.png)

# mipsmatch

`mipsmatch` is a utility for searching MIPS binaries for known functions, data, and segments. It calculates fingerprints
for overlay segments and functions and using those fingerprints to find identical code in other binary files. It's like
[`grep(1)`](https://man.freebsd.org/cgi/man.cgi?grep(1)) for MIPS.

Unlike grep, it's not easy to specify binary MIPS instructions at the command line to search for. `mipsmatch` lets you
fingerprint functions that are known and use those fingerprints to find the same function in other files.

This utility relies on GNU map and elf files created by `ld` at link time.\*

When decompiling a program, especially games and other software written for specific hardware (consoles) using very
specific compilers (SDKs) it is common for several files, or overlays to contain identical code. For example, multiple
stages in a game may share functions, items may all have the same utility functions, code from a game engine may appear
in overlays that are loaded dynamically, and most games will have statically linked code provided by the platform's SDK.
`mipsmatch` helps identify those common segments, and for projects that have reused this common code, will identify
segment offsets in new files that have yet to be decompiled.

`mipsmatch` can help find segment offsets and symbol addresses when [`splat`](https://github.com/ethteck/splat). It can
also help determine which SDK a game was compiled against, among other things.

`mipsmap` operates in two stages - the first creates a "match" file which contains fingerprints for segments and each of
the functions in that segment. The second stage uses that match file to find matches in another BIN file. This can be a
file that does not have `map` or `elf` files.

Match fingerprints are currently unstable and only guaranteed to match with the version of `mipsmatch` that generated
them.

`mipsmatch` was inspired by the `dups` tool written for [`sotn-decomp`](https://github.com/xeeynamo/sotn-decomp). Unlike
`dups`, `mipsmatch` finds identical segments. The major advantage is that fingerprints can be versioned, curated, and
distributed and finding matching fingerprints is a significantly cheaper operation than determining similarity.

`mipsmatch` is _fast_. Fingerprints can be created in linear time and matches are found in linear time as well. The
scale of a fingerprint search is only dependent on the size binary being searched.

## mipsmatch fingerprint

`fingerprint` is used to calculate segment and function fingerprints for all text symbols. It takes a map file in GNU map
format (lld or gold formats may or may not work) along with the target binary overlay that map was used to build. That
file can be either a compiled file or one from a game disk.

`fingerprint` will create a YAML document which can then be used by `scan` to find matching segments in another bin file.

Example:

```
mipsmatch --output build/us/match.cen.yaml fingerprint build/us/stcen.map build/us/stcen.elf
```

## mipsmatch scan

`scan` will find any segments defined in the match config if they exist in the binary passed as the second argument. The
output is a YAML stream where each document contains details about a segment match along with all function symbols which
matched in that segment.

Example:

```
mipsmatch scan build/us/match.cen.yaml disks/us/ST/RNO3/RNO3.BIN
```

The output format is a YAML stream where the top-level element in each document is a map with the following keys:

| Field      | Type    | Description      |
| ---------- | ------- | ---------------- |
| `name`     | string  | The segment name |
| `offset`   | number  | The offset where the segment was found in the file |
| `size`     | number  | The size of the segment |
| `symbols`  | symbol map | A map of symbol name to offset in the file |

Example match:

```yaml
name: prim_helpers
offset: 0x13270
size: 0x830
symbols:
  FindFirstUnkPrim2: 0x137D8
  PrimResetNext: 0x138DC
  UnkPolyFunc2: 0x139BC
  UnkPolyFunc0: 0x13A10
  UnkPrimHelper: 0x13270
  UpdateAnimation: 0x13658
  PrimDecreaseBrightness: 0x13A3C
  PrimToggleVisibility: 0x13854
  FindFirstUnkPrim: 0x137A8
```

## Use Cases

On `sotn-decomp` we found that several overlays of the same type (stages, weapons, familiars, etc.) reuse functions in
the same order with similar boundaries. Several tools have been written to identify duplicate functions, this is useful
for mapping symbols and sharing code, but it is still time consuming and problematic to find segment boundaries and
functions that have similar logic, but perform slightly different operations.

`mipsmatch` finds identical functions, but also groups them into their respective segments. It calculates fingerprints
for each segment, then ensures all of the functions exist in the same order within that segment when searching in other
binary files.

Stages on SotN have several common functions for managing entity layout, common items, rooms and other things. After
decompiling several stages, a pattern has emerged which allows those common functions to be broken up into segments.
These segments generally appear completely, or not at all, in a stage with limited exception.

One problem is that even though operations for these segments are identical, addresses and offsets that they use are
not. `mipsmatch` handles this by masking out possible global addresses. Other immediate values are kept when it is
unlikely they are used for calculating addresses.

`mipsmatch` uses map and elf files from compiled overlays to identify segments and symbols. The map file is used to
determine which source file is associated with each segment. By default `splat` strips this information from the elf
file. `static` functions are not included in the map file (even with `--print-map-locals`), so the elf file is used to
find all function symbols. The elf file also contains the binary image which is used for fingerprint calculation.

Fingerprints are created using Horner's Method. A radix and modulus have been chosen to optimize entropy for a 32-bit
fingerprint. Rabin-Karp is used to find these fingerprints in other files.

## What About…

### `coddog`

[`coddog`](https://github.com/ethteck/coddog) is another tool with similar behavior, but a few notable differences:

* it currently uses fuzzy matching and edit distance to determine equivalent functions.
* it's designed to find similar functions in one binary and while it can find functions across several binaries (like is
  common on disk-based systems), requires relatively heavy weight config for each bin to compare.
* in raw comparison mode (most similar to `mipsmatch`) it uses block-based hashes for each function which require
  $$O((n - m) \cdot m)$$ lookup time (where $$n$$ is the binary size, and $$m$$ is the size of the function being
  searched).

`mipsmatch` matches functions with identical operations and _most_ operands. It only masks out operands that could
contain global references. It uses previously built map and elf files to find equivalent functions and segments in
binary blobs without other configuration.

`mipsmatch` finds function or entire segment matches in linear ($$O(n)$$) time.

`coddog`'s MIPS handling and support is currently much more comprehensive than `mipsmatch`. `coddog` can also perform
fuzzy searches, which is not something `mipsmatch` has plans to implement.

### `bgrep`

I originally tried getting this to work by preprocessing extracted MIPS binaries and generating mask files then using
[`bgrep`](https://github.com/hohle/bgrep) to search files. This worked, but required generating a file with the binary
to match and a mask file per function. This became confusing an intractable.

## Built on the Shoulders of Giants

`mipsmatch` leverages several libraries used by your favorite decompilation tools:

* [mapfile_parser](https://github.com/Decompollaborate/mapfile_parser) for parsing… map files (what else?)
* [rust-elf](https://github.com/cole14/rust-elf) for parsing… ELF files (what else?)
* [rabbitizer](https://github.com/Decompollaborate/rabbitizer) for decoding MIPS instructions
