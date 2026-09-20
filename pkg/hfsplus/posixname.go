package hfsplus

import "strings"

// HFS+ catalog names may hold a slash, and io/fs path elements may not: macOS
// stores a name's POSIX colons as slashes and swaps them back when it resolves
// a path. GarageBand ships "Chasing Shadows Clap/Snare 01.loopdata", which a
// shell sees as "Chasing Shadows Clap:Snare 01.loopdata".
//
// The io/fs adapter therefore speaks POSIX names throughout. Without it such an
// entry is listed with a slash inside a single element, which is not a valid
// io/fs name, and no path can ever address it.

// posixName spells a catalog name the way a POSIX caller sees it.
func posixName(catalog string) string {
	if !strings.Contains(catalog, "/") {
		return catalog
	}
	return strings.ReplaceAll(catalog, "/", ":")
}

// catalogName spells one POSIX path element the way HFS+ stores it.
func catalogName(element string) string {
	if !strings.Contains(element, ":") {
		return element
	}
	return strings.ReplaceAll(element, ":", "/")
}
