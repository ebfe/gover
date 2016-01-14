gover
=====

Extract Go version out of Go binaries.

## Installation

    go get github.com/ebfe/gover

## Usage

    $ gover
    usage: gover <file>
    $ gover /path/to/some/go/binary
    go1.5.2
    $

## Bugs
- only detects Go 1.4+
- does not work on gcc-go compiled binaries
