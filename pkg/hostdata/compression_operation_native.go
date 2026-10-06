package hostdata

import "context"

// OpenNativeCompressionInput opens a native Darwin data file for read/write
// compression acquisition. The returned input is owned by Recompress after a
// successful opener callback; otherwise the caller must close it. Opening can
// itself decompress an existing compressed file. Symlinks follow native open
// behavior; callers requiring rooted containment must supply a rooted opener.
//
// This binding is specifically for native Darwin metadata. Foreign inputs on
// any host use an explicit CompressionInput with captured Darwin metadata and
// mount policy; this function never reinterprets native Windows/Linux flags.
func OpenNativeCompressionInput(ctx context.Context, name string) (CompressionInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return openNativeCompressionInput(ctx, name)
}
