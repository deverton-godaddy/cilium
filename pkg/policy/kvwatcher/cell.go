// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvwatcher

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Cell provides the KVstore policy watcher. The KVStore policy watcher watches
// for Cilium rules created/deleted under a key prefix specified through cilium
// config. It reads from the key and updates the policy repository (via
// PolicyManager) accordingly.
var Cell = cell.Module(
	"policy-kvstore-watcher",
	"Watches kvstore for cilium network policy updates",
	cell.Config(defaultConfig),
	cell.Provide(newKVPolicyResourcesWatcher,
		func() KVWatcherListStatus {
			return make(KVWatcherListStatus)
		}))

type PolicyManager interface {
	PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	PolicyDelete(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error)
}

type KVStoreBackend interface {
	Delete(ctx context.Context, key string) error
	ListAndWatch(ctx context.Context, prefix string, chanSize int) *kvstore.Watcher
}

type KVWatcherListStatus chan struct{}

type PolicyWatcherParams struct {
	cell.In

	ListStatus KVWatcherListStatus
	Lifecycle  cell.Lifecycle
	Logger     logrus.FieldLogger
}

type ResourcesWatcher interface {
	WatchKVPolicyResources(ctx context.Context, policyManager PolicyManager)
}

type PolicyResourcesWatcher struct {
	params PolicyWatcherParams
	cfg    Config
}

type Config struct {
	KVStorePolicyKeyPrefix string
}

const (
	// kvStorePolicyKeyPrefix defines the kvstore key for static cilium network policy yaml files.
	kvStorePolicyKeyPrefix = "kvstore-policy-key-prefix"
)

var defaultConfig = Config{
	KVStorePolicyKeyPrefix: "", // Disabled
}

func (cfg Config) Flags(flags *pflag.FlagSet) {
	flags.String(kvStorePolicyKeyPrefix, defaultConfig.KVStorePolicyKeyPrefix, "KVStore key prefix to watch and load Cilium network policy rules.")
}

func newKVPolicyResourcesWatcher(p PolicyWatcherParams, cfg Config) ResourcesWatcher {
	if cfg.KVStorePolicyKeyPrefix == "" {
		close(p.ListStatus)
		return nil
	}

	return &PolicyResourcesWatcher{
		params: p,
		cfg:    cfg,
	}
}

// WatchKVPolicyResources starts watching Cilium rules created under a key prefix.
func (p *PolicyResourcesWatcher) WatchKVPolicyResources(ctx context.Context, policyManager PolicyManager) {
	w := newPolicyWatcher(ctx, policyManager, p)
	w.watchKeyPrefix(ctx)
}

// newPolicyWatcher constructs a new policy watcher.
// This constructor unfortunately cannot be started via the Hive lifecycle as
// there exists a circular dependency between this watcher and the Daemon:
// The constructor newDaemon cannot complete before all pre-existing
// Cilium rules under a specific key have been added via the PolicyManager
// (i.e. watchKeyPrefix has observed the entire key prefix).
// Because the PolicyManager interface itself is implemented by the Daemon
// struct, we have a circular dependency.
func newPolicyWatcher(ctx context.Context, policyManager PolicyManager, p *PolicyResourcesWatcher) *policyWatcher {
	w := &policyWatcher{
		log:           p.params.Logger,
		policyManager: policyManager,
		backend:       kvstore.Client(),
		listStatus:    p.params.ListStatus,
		config:        p.cfg,
		rulesCache:    make(map[string]*api.Rules),
	}
	return w
}
