//go:build !unix

package adapters

// openFlags is empty where named pipes do not live in the filesystem tree.
const openFlags = 0
