package kvwatcher

import (
	"io"
	"testing"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakePolicyManager struct {
	OnPolicyAdd    func(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	OnPolicyDelete func(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error)
}

func (f *fakePolicyManager) PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error) {
	if f.OnPolicyAdd != nil {
		return f.OnPolicyAdd(rules, opts)
	}
	panic("OnPolicyAdd(api.Rules, *policy.AddOptions) (uint64, error) was called and is not set!")
}

func (f *fakePolicyManager) PolicyDelete(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error) {
	if f.OnPolicyDelete != nil {
		return f.OnPolicyDelete(labels, opts)
	}
	panic("OnPolicyDelete(labels.LabelArray, *policy.DeleteOptions) (uint64, error) was called and is not set!")
}

func TestOnUpsert(t *testing.T) {
	fakeLogger := logrus.New()
	fakeLogger.SetOutput(io.Discard)

	policyAdd := make(chan api.Rules, 1)
	fakePolicyManager := &fakePolicyManager{
		OnPolicyAdd: func(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error) {
			policyAdd <- rules
			return 0, nil
		},
	}

	p := &policyWatcher{
		log:           fakeLogger,
		policyManager: fakePolicyManager,
		rulesCache:    make(map[string]*api.Rules),
	}

	rulesToAdd := &api.Rules{
		api.NewRule().
			WithEndpointSelector(
				api.NewESFromLabels(labels.ParseLabel("$host")),
			),
	}
	key := "test-key"
	resourceID := ipcacheTypes.ResourceID("test-resource")

	err := p.onUpsert(rulesToAdd, key, resourceID)
	assert.NoError(t, err)
	assert.Equal(t, rulesToAdd, p.rulesCache[key])

	rulesAdded := <-policyAdd
	assert.Len(t, rulesAdded, 1)
	assert.Equal(t, "[kvstore:key=test-key]", rulesAdded[0].Labels.String())

	// upsert unmodified rules should not trigger a policy add
	err = p.onUpsert(rulesToAdd, key, resourceID)
	assert.NoError(t, err)
	assert.Equal(t, rulesToAdd, p.rulesCache[key])
	assert.Equal(t, 0, len(policyAdd))
}

func TestOnDelete(t *testing.T) {
	fakeLogger := logrus.New()
	fakeLogger.SetOutput(io.Discard)

	policyDelete := make(chan ipcacheTypes.ResourceID, 1)
	fakePolicyManager := &fakePolicyManager{
		OnPolicyDelete: func(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error) {
			policyDelete <- opts.Resource
			return 0, nil
		},
	}

	p := &policyWatcher{
		log:           fakeLogger,
		policyManager: fakePolicyManager,
		rulesCache:    make(map[string]*api.Rules),
	}

	rulesToDelete := &api.Rules{
		api.NewRule().
			WithEndpointSelector(
				api.NewESFromLabels(labels.ParseLabel("$host")),
			),
	}
	key := "test-key"
	resourceID := ipcacheTypes.ResourceID("test-resource")

	p.rulesCache[key] = rulesToDelete
	err := p.onDelete(rulesToDelete, key, resourceID)
	assert.NoError(t, err)
	assert.Nil(t, p.rulesCache[key])

	rulesDeleted := <-policyDelete
	assert.Equal(t, resourceID, rulesDeleted)
}
