// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package unikernel

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/BurntSushi/toml"
	vc "github.com/kata-containers/runtime/virtcontainers"
)

const (
	metaDataFilename = "meta"
)

// Config returns a unikernel configuration
func Config(ocispec CompatOCISpec, runtime RuntimeConfig, bundlePath, cid, console string, detach bool) (vc.UnikernelConfig, error) {
	var config vc.UnikernelConfig
	metadataPath := filepath.Join(bundlePath, metaDataFilename)
	metadata, err := ioutil.ReadFile(metadataPath)
	if err != nil {
		return config, fmt.Errorf("Could not read metadata file: %v", err)
	}

	_, err = toml.Decode(string(configData), &config)
	if err != nil {
		return config, fmt.Errorf("Could not decode metadata file: %v", err)
	}

	return config, nil
}
