// Copyright (c) 2017 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"path/filepath"
	"sync"

	deviceManager "github.com/kata-containers/runtime/virtcontainers/device/manager"
)

type unikernelType string

// UnikernelConfig is the unikernel configuration
type UnikernelConfig struct {
	Type  unikernelType `toml:"type"`
	Image string        `toml:"image"`
}

func newContainerUnikernel(config UnikernelConfig) (VCUnikernel, error) {
	unikernel, err := newUnikernel(config)
	if err != nil {
		return nil, err
	}

	network := newNetwork(sandboxConfig.NetworkModel)

	s := &Sandbox{
		id:              sandboxConfig.ID,
		hypervisor:      hypervisor,
		agent:           agent,
		storage:         &filesystem{},
		network:         network,
		config:          &sandboxConfig,
		devManager:      deviceManager.NewDeviceManager(sandboxConfig.HypervisorConfig.BlockDeviceDriver),
		volumes:         sandboxConfig.Volumes,
		runPath:         filepath.Join(runStoragePath, sandboxConfig.ID),
		configPath:      filepath.Join(configStoragePath, sandboxConfig.ID),
		state:           State{},
		annotationsLock: &sync.RWMutex{},
		wg:              &sync.WaitGroup{},
	}

	if err = globalSandboxList.addSandbox(s); err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			s.Logger().WithError(err).WithField("sandboxid", s.id).Error("Create new sandbox failed")
			globalSandboxList.removeSandbox(s.id)
		}
	}()

	if err = s.storage.createAllResources(s); err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			s.storage.deleteSandboxResources(s.id, nil)
		}
	}()

	// FIXME: create qemu_unikernel
	if err = s.hypervisor.init(s); err != nil {
		return nil, err
	}

	if err = s.hypervisor.createSandbox(sandboxConfig); err != nil {
		return nil, err
	}

	agentConfig := newAgentConfig(sandboxConfig)
	if err = s.agent.init(s, agentConfig); err != nil {
		return nil, err
	}

	return s, nil
}

// import (
// 	vc "github.com/kata-containers/runtime/virtcontainers"
// 	"github.com/kata-containers/runtime/virtcontainers/pkg/oci"
// )

// type Unikernel interface {
// 	CreateContainer() vc.Process
// }

// func NewUnikernel() Unikernel {
// 	return &Rumprun{}
// }

type Rumprun struct {
}

// func (r *Rumprun) CreateContainer(ociSpec oci.CompatOCISpec, runtimeConfig oci.RuntimeConfig, containerID, bundlePath, console string, disableOutput bool) vc.Process {
// 	//   - set kernel parameters
// 	//   - network config
// 	//   - start VM
// 	//   - set network
// 	//   see createSandboxFromConfig
// }
