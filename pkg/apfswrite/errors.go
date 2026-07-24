// SPDX-License-Identifier: GPL-2.0-only
// Ported from mkapfs (apfsprogs) — Copyright (C) 2019 Ernesto A. Fernández. Go port Copyright (C) 2024 Deployment Theory.

package apfswrite

import "errors"

var (
	errDeviceTooBig   = errors.New("apfswrite: device is too big")
	errIPPoolTooBig   = errors.New("apfswrite: internal pool too big for the main device")
	errCabUnsupported = errors.New("apfswrite: container too large (cib-address-block layer not supported)")
	errFileDataTooBig = errors.New("apfswrite: file data and metadata do not fit in the container")
)
