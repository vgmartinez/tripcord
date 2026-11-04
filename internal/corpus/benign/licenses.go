package benign

import "slices"

// spdxLicenses is the SPDX identifier GitHub's license API returns for
// every license in the licensee catalog it serves (GET /licenses/{key}),
// plus NOASSERTION for a repository whose license the API does not
// identify. The list is sorted for lookup.
var spdxLicenses = []string{
	"0BSD",
	"AFL-3.0",
	"AGPL-3.0",
	"Apache-2.0",
	"Artistic-2.0",
	"BSD-2-Clause",
	"BSD-3-Clause",
	"BSD-3-Clause-Clear",
	"BSD-4-Clause",
	"BSL-1.0",
	"CC-BY-4.0",
	"CC-BY-SA-4.0",
	"CC0-1.0",
	"CECILL-2.1",
	"CERN-OHL-P-2.0",
	"CERN-OHL-S-2.0",
	"CERN-OHL-W-2.0",
	"ECL-2.0",
	"EPL-1.0",
	"EPL-2.0",
	"EUPL-1.1",
	"EUPL-1.2",
	"GFDL-1.3",
	"GPL-2.0",
	"GPL-3.0",
	"ISC",
	"LGPL-2.1",
	"LGPL-3.0",
	"LPPL-1.3c",
	"MIT",
	"MIT-0",
	"MPL-2.0",
	"MS-PL",
	"MS-RL",
	"MulanPSL-2.0",
	"NCSA",
	"NOASSERTION",
	"ODbL-1.0",
	"OFL-1.1",
	"OSL-3.0",
	"PostgreSQL",
	"UPL-1.0",
	"Unlicense",
	"Vim",
	"WTFPL",
	"Zlib",
}

func knownLicense(id string) bool {
	_, ok := slices.BinarySearch(spdxLicenses, id)
	return ok
}
