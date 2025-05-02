# mipsmatch


`mipsmatch` is a tool for calculating fingerprints for overlay segments and functions that have been previously built
and then searching for those signatures in other overlay files. This utility relies on GNU map and elf files created by
`ld` at link time.\*

It's common for overlays of the same type to contain identical code. Multiple stages in a game may share functions,
items may all have the same utility functions, and even code from a game engine may appear in overlays that are loaded
dynamically. `mipsmatch` helps identify those common segments, and for projects that have reused this common code, will
identify segment offsets in new files that have yet to be decompiled.

This can be combined with `splat` to generate segment offsets.

`mipsmap` operates in two stages - the first creates a "match" file which contains fingerprints for segments and each of
the functions in that segment. The second stage uses that match file to find matches in another BIN file. This can be a
file that does not have `map` or `elf` files.

Match fingerprints are currently unstable and only gauranteed to match with the version of `mipsmatch` that generated
them.

`mipsmatch` was inspired by the `dups` tool written for [`sotn-decomp`](https://github.com/xeeynamo/sotn-decomp). Unlike
`dups`, `mipsmatch` finds identical segments. The major advantage is that fingerprints can be versioned, curated, and
distributed and finding matching fingerprints is a significantly cheaper operation than determining similarity.

## mipsmatch evaluate

`evaluate` is used to calculate segment and function fingerprints for all text symbols. It takes a map file in GNU map
format (lld or gold formats may or may not work) along with the target binary overlay that map was used to build. That
file can be either a compiled file or one from a game disk.

`evaluate` will create a YAML document which can then be used by `scan` to find matching segments in another bin file.

Example:

```
mipsmatch --output build/us/match.cen.yaml evaluate build/us/stcen.map build/us/stcen.elf
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
| `sections` | map     | A map where keys are a section type and values contain section information described below |

The section map

| Field     | Type    | Description       |
| --------- | ------- | ----------------- |
| `offset`  | size\_t | The offset in the scanned
| `size`    | size\_t |
| `section` | map     | A map where the key is the section type and the value is a map of symbol to offset |
---
name: prim_helpers
offset: 301360
size: 2096
symbols:
  UnkPrimHelper: 301360
  PrimDecreaseBrightness: 303356
  FindFirstUnkPrim2: 302744
  FindFirstUnkPrim: 302696
  UnkPolyFunc2: 303228
  UnkPolyFunc0: 303312
  PrimResetNext: 303004
  UpdateAnimation: 302360
  PrimToggleVisibility: 302868

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
