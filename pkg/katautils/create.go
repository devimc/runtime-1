// Copyright (c) 2018 Intel Corporation
// Copyright (c) 2018 HyperHQ Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

package katautils

import (
	"context"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"syscall"

	vc "github.com/kata-containers/runtime/virtcontainers"
	vf "github.com/kata-containers/runtime/virtcontainers/factory"
	"github.com/kata-containers/runtime/virtcontainers/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// GetKernelParamsFunc use a variable to allow tests to modify its value
var GetKernelParamsFunc = getKernelParams

var mountRootfsFunc = mountRootfs

var systemdKernelParam = []vc.Param{
	{
		Key:   "systemd.unit",
		Value: systemdUnitName,
	},
	{
		Key:   "systemd.mask",
		Value: "systemd-networkd.service",
	},
	{
		Key:   "systemd.mask",
		Value: "systemd-networkd.socket",
	},
}

func getKernelParams(needSystemd, trace bool) []vc.Param {
	p := []vc.Param{}

	if needSystemd {
		p = append(p, systemdKernelParam...)
	}

	return p
}

func needSystemd(config vc.HypervisorConfig) bool {
	return config.ImagePath != ""
}

// HandleFactory  set the factory
func HandleFactory(ctx context.Context, vci vc.VC, runtimeConfig *oci.RuntimeConfig) {
	if !runtimeConfig.FactoryConfig.Template && runtimeConfig.FactoryConfig.VMCacheNumber == 0 {
		return
	}
	factoryConfig := vf.Config{
		Template:        runtimeConfig.FactoryConfig.Template,
		TemplatePath:    runtimeConfig.FactoryConfig.TemplatePath,
		VMCache:         runtimeConfig.FactoryConfig.VMCacheNumber > 0,
		VMCacheEndpoint: runtimeConfig.FactoryConfig.VMCacheEndpoint,
		VMConfig: vc.VMConfig{
			HypervisorType:   runtimeConfig.HypervisorType,
			HypervisorConfig: runtimeConfig.HypervisorConfig,
			AgentType:        runtimeConfig.AgentType,
			AgentConfig:      runtimeConfig.AgentConfig,
			ProxyType:        runtimeConfig.ProxyType,
			ProxyConfig:      runtimeConfig.ProxyConfig,
		},
	}

	kataUtilsLogger.WithField("factory", factoryConfig).Info("load vm factory")

	f, err := vf.NewFactory(ctx, factoryConfig, true)
	if err != nil && !factoryConfig.VMCache {
		kataUtilsLogger.WithError(err).Warn("load vm factory failed, about to create new one")
		f, err = vf.NewFactory(ctx, factoryConfig, false)
	}
	if err != nil {
		kataUtilsLogger.WithError(err).Warn("create vm factory failed")
		return
	}

	vci.SetFactory(ctx, f)
}

// SetEphemeralStorageType sets the mount type to 'ephemeral'
// if the mount source path is provisioned by k8s for ephemeral storage.
// For the given pod ephemeral volume is created only once
// backed by tmpfs inside the VM. For successive containers
// of the same pod the already existing volume is reused.
func SetEphemeralStorageType(ociSpec specs.Spec) specs.Spec {
	for idx, mnt := range ociSpec.Mounts {
		if vc.IsEphemeralStorage(mnt.Source) {
			ociSpec.Mounts[idx].Type = vc.KataEphemeralDevType
		}
		if vc.Isk8sHostEmptyDir(mnt.Source) {
			ociSpec.Mounts[idx].Type = vc.KataLocalDevType
		}
	}
	return ociSpec
}

// CreateSandbox create a sandbox container
func CreateSandbox(ctx context.Context, vci vc.VC, ociSpec specs.Spec, runtimeConfig oci.RuntimeConfig, rootFs vc.RootFs,
	containerID, bundlePath, console, consoleSocket string, disableOutput, systemdCgroup, builtIn bool) (_ vc.VCSandbox, _ vc.Process, err error) {
	if err := NewPersistentNamespaces(containerID, "", ociSpec.Linux.Namespaces); err != nil {
		return nil, vc.Process{}, err
	}

	span, ctx := Trace(ctx, "createSandbox")
	defer span.Finish()

	consolePath, err := SetupConsole(console, consoleSocket)
	if err != nil {
		return nil, vc.Process{}, err
	}

	sandboxConfig, err := oci.SandboxConfig(ociSpec, runtimeConfig, bundlePath, containerID, consolePath, disableOutput, systemdCgroup)
	if err != nil {
		return nil, vc.Process{}, err
	}

	if builtIn {
		sandboxConfig.Stateful = true
	}

	if err := checkForFIPS(&sandboxConfig); err != nil {
		return nil, vc.Process{}, err
	}

	if !rootFs.Mounted && len(sandboxConfig.Containers) == 1 {
		if rootFs.Source != "" {
			realPath, err := ResolvePath(rootFs.Source)
			if err != nil {
				return nil, vc.Process{}, err
			}
			rootFs.Source = realPath
		}
		sandboxConfig.Containers[0].RootFs = rootFs
	}

	// FIXME: remove
	// // Important to create the network namespace before the sandbox is
	// // created, because it is not responsible for the creation of the
	// // netns if it does not exist.
	// if err := SetupNetworkNamespace(&sandboxConfig.NetworkConfig); err != nil {
	// 	return nil, vc.Process{}, err
	// }

	defer func() {
		// cleanup netns if kata creates it
		ns := sandboxConfig.NetworkConfig
		if err != nil && ns.NetNsCreated {
			if ex := cleanupNetNS(ns.NetNSPath); ex != nil {
				kataUtilsLogger.WithField("path", ns.NetNSPath).WithError(ex).Warn("failed to cleanup netns")
			}
		}
	}()

	// Run pre-start OCI hooks.
	err = EnterNetNS(sandboxConfig.NetworkConfig.NetNSPath, func() error {
		return PreStartHooks(ctx, ociSpec, containerID, bundlePath)
	})
	if err != nil {
		return nil, vc.Process{}, err
	}

	sandbox, err := vci.CreateSandbox(ctx, sandboxConfig)
	if err != nil {
		return nil, vc.Process{}, err
	}

	sid := sandbox.ID()
	kataUtilsLogger = kataUtilsLogger.WithField("sandbox", sid)
	span.SetTag("sandbox", sid)

	containers := sandbox.GetAllContainers()
	if len(containers) != 1 {
		return nil, vc.Process{}, fmt.Errorf("BUG: Container list from sandbox is wrong, expecting only one container, found %d containers", len(containers))
	}

	if !builtIn {
		err = AddContainerIDMapping(ctx, containerID, sandbox.ID())
		if err != nil {
			return nil, vc.Process{}, err
		}
	}

	return sandbox, containers[0].Process(), nil
}

var procFIPS = "/proc/sys/crypto/fips_enabled"

func checkForFIPS(sandboxConfig *vc.SandboxConfig) error {
	content, err := ioutil.ReadFile(procFIPS)
	if err != nil {
		// In case file cannot be found or read, simply return
		return nil
	}

	enabled, err := strconv.Atoi(strings.Trim(string(content), "\n\t "))
	if err != nil {
		// Unexpected format, ignore and simply return early
		return nil
	}

	if enabled == 1 {
		param := vc.Param{
			Key:   "fips",
			Value: "1",
		}

		if err := sandboxConfig.HypervisorConfig.AddKernelParam(param); err != nil {
			return fmt.Errorf("Error enabling fips mode : %v", err)
		}
	}

	return nil
}

// CreateContainer create a container
func CreateContainer(ctx context.Context, vci vc.VC, sandbox vc.VCSandbox, ociSpec specs.Spec, rootFs vc.RootFs, containerID, bundlePath, console, consoleSocket string, disableOutput, builtIn bool) (p vc.Process, err error) {
	var c vc.VCContainer
	sandboxID, err := oci.SandboxID(ociSpec)
	if err != nil {
		return
	}

	if err = NewPersistentNamespaces(sandboxID, containerID, ociSpec.Linux.Namespaces); err != nil {
		return
	}

	defer func() {
		if err != nil {
			if e := RemovePersistentNamespaces(sandboxID, containerID); e != nil {
				kataUtilsLogger.WithError(e).Warn("Could not remove persisten namespaces")
			}
		}
	}()

	span, ctx := Trace(ctx, "createContainer")
	defer span.Finish()

	ociSpec = SetEphemeralStorageType(ociSpec)

	var consolePath string
	consolePath, err = SetupConsole(console, consoleSocket)
	if err != nil {
		return
	}

	contConfig, err := oci.ContainerConfig(ociSpec, bundlePath, containerID, consolePath, disableOutput)
	if err != nil {
		return
	}

	if !rootFs.Mounted {
		if rootFs.Source != "" {
			var realPath string
			realPath, err = ResolvePath(rootFs.Source)
			if err != nil {
				return
			}
			rootFs.Source = realPath
		}
		contConfig.RootFs = rootFs
	}

	var rootfs string
	rootfs, err = mountRootfsFunc(contConfig.RootFs.Source)
	if err != nil {
		return
	}

	defer func() {
		if err != nil && rootfs != "" {
			if e := syscall.Unmount(rootfs, 0); e != nil {
				kataUtilsLogger.WithError(e).WithField("rootfs", rootfs).Warn("Could not unmount rootfs")
			}
		}
	}()

	span.SetTag("sandbox", sandboxID)

	if builtIn {
		c, err = sandbox.CreateContainer(contConfig)
		if err != nil {
			return
		}
	} else {
		kataUtilsLogger = kataUtilsLogger.WithField("sandbox", sandboxID)

		sandbox, c, err = vci.CreateContainer(ctx, sandboxID, contConfig)
		if err != nil {
			return
		}

		if err = AddContainerIDMapping(ctx, containerID, sandboxID); err != nil {
			return
		}
	}

	// Run pre-start OCI hooks.
	if err = PreStartHooks(ctx, ociSpec, containerID, bundlePath); err != nil {
		return
	}

	return c.Process(), nil
}

func mountRootfs(rootfs string) (string, error) {
	// Sandbox's mount namespaces was created before this container, hence
	// the rootfs for this container must be mounted to make it visible
	info, err := GetFsInfo(rootfs)
	if err != nil {
		return "", err
	}

	if err = syscall.Mount(info.Device, info.MountPoint, info.FsType, uintptr(info.Flags), info.Data); err != nil {
		return "", err
	}

	return info.MountPoint, nil
}
