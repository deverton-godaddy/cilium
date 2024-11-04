// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvwatcher

import (
	"fmt"
	"time"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
	"github.com/sirupsen/logrus"
)

// read cilium rules json and convert to policy object and
// add rules to policy engine.
func (p *policyWatcher) onUpsert(rules *api.Rules, key string, resourceID ipcacheTypes.ResourceID) error {
	initialRecvTime := time.Now()

	oldRules, ok := p.rulesCache[key]
	if ok {
		if oldRules.DeepEqual(rules) {
			return nil
		}

		p.log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: key,
		}).Debug("Modified CiliumNetworkPolicy")
	}

	translatedRules := rules.DeepCopy()
	lbls := getLabels(key)

	for _, rule := range translatedRules {
		if err := rule.Sanitize(); err != nil {
			return fmt.Errorf("Unable to sanitize network policy: %w", err)
		}

		rule.Labels = append(lbls, rule.Labels...).Sort()
	}

	err := p.upsertRules(translatedRules, initialRecvTime, resourceID)
	if err == nil {
		p.rulesCache[key] = rules
	}

	return err
}

func (p *policyWatcher) onDelete(rules *api.Rules, key string, resourceID ipcacheTypes.ResourceID) error {
	err := p.deleteRules(resourceID)
	delete(p.rulesCache, key)
	return err
}

// upsertRules adds or updates the rules in the policy engine.
// If the rules were successfully imported, the raw (i.e. untranslated) rules
// are also added to p.rulesCache.
func (p *policyWatcher) upsertRules(rules api.Rules, initialRecvTime time.Time, resourceID ipcacheTypes.ResourceID) error {
	scopedLog := p.log.WithFields(logrus.Fields{
		logfields.Resource: resourceID,
	})

	scopedLog.Debug("Adding CiliumNetworkPolicy")

	_, policyImportErr := p.policyManager.PolicyAdd(rules, &policy.AddOptions{
		Source:              source.KVStore,
		ProcessingStartTime: initialRecvTime,
		Resource:            resourceID,
		ReplaceByResource:   true,
	})

	if policyImportErr != nil {
		scopedLog.WithError(policyImportErr).Warn("Unable to add CiliumNetworkPolicy")
	} else {
		scopedLog.Info("Imported CiliumNetworkPolicy")
	}

	return policyImportErr
}

func (p *policyWatcher) deleteRules(resourceID ipcacheTypes.ResourceID) error {
	scopedLog := p.log.WithFields(logrus.Fields{
		logfields.Resource: resourceID,
	})

	scopedLog.Debug("Deleting CiliumNetworkPolicy")

	_, err := p.policyManager.PolicyDelete(nil, &policy.DeleteOptions{
		Source:           source.KVStore,
		Resource:         resourceID,
		DeleteByResource: true,
	})
	if err == nil {
		scopedLog.Info("Deleted CiliumNetworkPolicy")
	} else {
		scopedLog.WithError(err).Warn("Unable to delete CiliumNetworkPolicy")
	}
	return err
}

// reportCNPChangeMetrics generates metrics for changes (Add, Update, Delete) to
// Cilium Network Policies depending on the operation's success.
func reportCNPChangeMetrics(err error) {
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
	} else {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	}
}
