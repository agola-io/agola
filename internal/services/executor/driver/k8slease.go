// Copyright 2019 Sorint.lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
// See the License for the specific language governing permissions and
// limitations under the License.

package driver

import (
	"context"
	"encoding/json"
	"time"

	errors "golang.org/x/xerrors"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apilabels "k8s.io/apimachinery/pkg/labels"
)

type LeaseData struct {
	LeaseDurationSeconds int       `json:"leaseDurationSeconds"`
	AcquireTime          time.Time `json:"acquireTime"`
	RenewTime            time.Time `json:"renewTime"`
	HolderIdentity       string    `json:"holderIdentity"`
}

func (d *K8sDriver) updateLease(ctx context.Context) error {
	duration := int(staleExecutorLeaseInterval / time.Second)
	now := time.Now()

	name := executorLeasePrefix + d.executorID
	labels := map[string]string{}
	labels[executorsGroupIDKey] = d.executorsGroupID
	labels[executorIDKey] = d.executorID

	if d.useLeaseAPI {
		duration := int32(duration)
		now := metav1.MicroTime{Time: now}

		leaseClient := d.client.CoordinationV1().Leases(d.namespace)
		found := false
		lease, err := leaseClient.Get(name, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return err
			}
		} else {
			found = true
		}

		if found {
			lease.Spec.RenewTime = &now
			_, err := leaseClient.Update(lease)
			return err
		}

		lease = &coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: labels,
			},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       &d.executorID,
				LeaseDurationSeconds: &duration,
				AcquireTime:          &now,
				RenewTime:            &now,
			},
		}
		_, err = leaseClient.Create(lease)
		return err
	} else {
		cmClient := d.client.CoreV1().ConfigMaps(d.namespace)
		found := false
		cm, err := cmClient.Get(name, metav1.GetOptions{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return err
			}
		} else {
			found = true
		}

		ld := &LeaseData{
			LeaseDurationSeconds: duration,
			AcquireTime:          now,
			HolderIdentity:       d.executorID,
			RenewTime:            now,
		}
		if found {
			if cm.Annotations == nil {
				// this shouldn't happen
				return errors.Errorf("missing configmap lease annotations")
			}
			if recordBytes, found := cm.Annotations[cmLeaseKey]; found {
				if err := json.Unmarshal([]byte(recordBytes), &ld); err != nil {
					return err
				}
			}
			ld.RenewTime = now
			ldj, err := json.Marshal(ld)
			if err != nil {
				return err
			}
			cm.Annotations[cmLeaseKey] = string(ldj)
			_, err = cmClient.Update(cm)
			return err
		}

		ldj, err := json.Marshal(ld)
		if err != nil {
			return err
		}
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name,
				Labels:      labels,
				Annotations: make(map[string]string),
			},
		}
		cm.Annotations[cmLeaseKey] = string(ldj)
		_, err = cmClient.Create(cm)
		return err
	}
}

func (d *K8sDriver) getLeases(ctx context.Context) ([]string, error) {
	executorsIDs := []string{}

	labels := map[string]string{}
	labels[executorsGroupIDKey] = d.executorsGroupID

	if d.useLeaseAPI {
		leaseClient := d.client.CoordinationV1().Leases(d.namespace)

		leases, err := leaseClient.List(metav1.ListOptions{LabelSelector: apilabels.SelectorFromSet(labels).String()})
		if err != nil {
			return nil, err
		}
		for _, lease := range leases.Items {
			if v, ok := lease.Labels[executorIDKey]; ok {
				executorsIDs = append(executorsIDs, v)
			}
		}
	} else {
		cmClient := d.client.CoreV1().ConfigMaps(d.namespace)

		cms, err := cmClient.List(metav1.ListOptions{LabelSelector: apilabels.SelectorFromSet(labels).String()})
		if err != nil {
			return nil, err
		}
		for _, cm := range cms.Items {
			if v, ok := cm.Labels[executorIDKey]; ok {
				executorsIDs = append(executorsIDs, v)
			}
		}
	}

	return executorsIDs, nil
}

func (d *K8sDriver) cleanStaleExecutorsLease(ctx context.Context) error {
	labels := map[string]string{}
	labels[executorsGroupIDKey] = d.executorsGroupID

	if d.useLeaseAPI {
		leaseClient := d.client.CoordinationV1().Leases(d.namespace)

		leases, err := d.leaseLister.List(apilabels.SelectorFromSet(labels))
		if err != nil {
			return err
		}
		for _, lease := range leases {
			if lease.Spec.HolderIdentity == nil {
				d.log.Warnf("missing holder identity for lease %q", lease.Name)
				continue
			}
			// skip our lease
			if *lease.Spec.HolderIdentity == d.executorID {
				continue
			}
			if lease.Spec.RenewTime == nil {
				d.log.Warnf("missing renew time for lease %q", lease.Name)
				continue
			}
			if lease.Spec.RenewTime.Add(staleExecutorLeaseInterval).Before(time.Now()) {
				d.log.Infof("deleting stale lease %q", lease.Name)
				if err := leaseClient.Delete(lease.Name, nil); err != nil {
					d.log.Errorf("failed to delete stale lease %q, err: %v", lease.Name, err)
				}
			}
		}
	} else {
		cmClient := d.client.CoreV1().ConfigMaps(d.namespace)

		cms, err := d.cmLister.List(apilabels.SelectorFromSet(labels))
		if err != nil {
			return err
		}
		for _, cm := range cms {
			var ld *LeaseData
			if cm.Annotations == nil {
				// this shouldn't happen
				d.log.Warnf("missing configmap lease annotations for configmap %q", cm.Name)
				continue
			}
			if recordBytes, found := cm.Annotations[cmLeaseKey]; found {
				if err := json.Unmarshal([]byte(recordBytes), &ld); err != nil {
					return err
				}
			}
			// skip our lease
			if ld.HolderIdentity == d.executorID {
				continue
			}
			if ld.RenewTime.Add(staleExecutorLeaseInterval).Before(time.Now()) {
				d.log.Infof("deleting stale configmap lease %q", cm.Name)
				if err := cmClient.Delete(cm.Name, nil); err != nil {
					d.log.Errorf("failed to delete stale configmap lease %q, err: %v", cm.Name, err)
				}
			}
		}
	}
	return nil
}
