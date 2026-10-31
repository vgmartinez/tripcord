// Package adapters defines harness adapters and their shared safe file reader.
// Adapters parse untrusted harness config into the normalized model. They must
// use SafeReader for every repository file read and must never execute config,
// invoke hooks, or start a harness.
package adapters
