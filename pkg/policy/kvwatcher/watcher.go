// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvwatcher

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/validation"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type policyWatcher struct {
	log           logrus.FieldLogger
	config        Config
	policyManager PolicyManager
	backend       KVStoreBackend
	listStatus    KVWatcherListStatus

	rulesCache map[string]*api.Rules
}

func (p *policyWatcher) watchKeyPrefix(ctx context.Context) {
	go func() {
		prefixEvents := p.backend.ListAndWatch(ctx, p.config.KVStorePolicyKeyPrefix, 512)
		defer prefixEvents.Stop()

		for {
			select {
			case event, ok := <-prefixEvents.Events:
				if !ok {
					return
				}

				if event.Typ == kvstore.EventTypeListDone {
					close(p.listStatus)
					continue
				}

				keyName := strings.TrimPrefix(event.Key, p.config.KVStorePolicyKeyPrefix)
				if keyName[0] == '/' {
					keyName = keyName[1:]
				}

				if reasons := validation.IsDNS1123Subdomain(keyName); len(reasons) > 0 {
					p.log.WithFields(logrus.Fields{
						"name":    keyName,
						"key":     event.Key,
						"reasons": reasons,
					}).Error("CNP name parse validation failed")
					continue
				}

				var err error

				rules, err := translateToCiliumRules(event.Value)
				if err != nil {
					p.log.WithError(err).
						WithFields(logrus.Fields{
							"name": keyName,
							"key":  event.Key,
						}).Error("CNP parse failed")
					reportCNPChangeMetrics(err)
					continue
				}

				resourceID := ipcacheTypes.NewResourceID(
					ipcacheTypes.ResourceKindKVStore,
					p.config.KVStorePolicyKeyPrefix,
					keyName,
				)

				switch event.Typ {
				case kvstore.EventTypeCreate, kvstore.EventTypeModify:
					err = p.onUpsert(rules, keyName, resourceID)
				case kvstore.EventTypeDelete:
					err = p.onDelete(rules, keyName, resourceID)
				}
				reportCNPChangeMetrics(err)
			}
		}
	}()
}

func translateToCiliumRules(jsonData []byte) (*api.Rules, error) {
	// translate json to rules object
	rules := api.Rules{}
	err := json.Unmarshal(jsonData, &rules)
	if err != nil {
		return nil, err
	}
	return &rules, nil
}

func getLabels(key string) labels.LabelArray {
	labelsArr := labels.LabelArray{
		labels.NewLabel("key", key, labels.LabelSourceKVStore),
	}
	return labelsArr
}
