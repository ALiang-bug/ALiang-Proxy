// Development-only verification of downloaded module source against go.sum.
// Local replacements are inspected separately and are not module-cache artifacts.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/mod/sumdb/dirhash"
)

type module struct {
	Path, Version, Dir string
	Replace            *module
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: verifydeps packages.json go.sum")
	}
	sumsFile, err := os.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer sumsFile.Close()
	sums := map[string]string{}
	scan := bufio.NewScanner(sumsFile)
	for scan.Scan() {
		f := strings.Fields(scan.Text())
		if len(f) == 3 {
			sums[f[0]+" "+f[1]] = f[2]
		}
	}
	if scan.Err() != nil {
		panic(scan.Err())
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	seen := map[string]bool{}
	verified, local := 0, 0
	for {
		var p struct{ Module *module }
		if err = decoder.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
		m := p.Module
		if m == nil || seen[m.Path] {
			continue
		}
		seen[m.Path] = true
		if m.Replace != nil || m.Version == "" {
			local++
			continue
		}
		expected, found := sums[m.Path+" "+m.Version]
		if !found {
			panic("module checksum missing: " + m.Path)
		}
		actual, err := dirhash.HashDir(m.Dir, m.Path+"@"+m.Version, dirhash.DefaultHash)
		if err != nil || actual != expected {
			panic("module source mismatch: " + m.Path)
		}
		verified++
	}
	fmt.Printf("Verified %d actual downloaded dependency source trees against go.sum; %d local modules require archive/patch/source review.\n", verified, local)
}
