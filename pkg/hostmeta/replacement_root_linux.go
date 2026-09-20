package hostmeta

import "os"

func prepareReplacementAt(_ *os.File, stage *os.Root, _ os.FileInfo) (*os.File, error) {
	return stage.OpenFile("replacement", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
}

func restoreReplacementMetadataAt(source, target *os.File, info os.FileInfo) error {
	return restoreReplacementMetadata(source, target, info)
}
