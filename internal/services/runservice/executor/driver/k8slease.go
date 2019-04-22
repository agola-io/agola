// This file is part of Agola
//
// Copyright (C) 2019 Sorint.lab
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package driver

import (
	"context"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
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
		now := metav1.MicroTime{now}

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
		lease, err = leaseClient.Create(lease)
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
		cm, err = cmClient.Create(cm)
		return err
	}
	return nil
}

func (d *K8sDriver) getLeases(ctx context.Context) ([]string, error) {
	executorsIDs := []string{}

	labels := map[string]string{}
	labels[executorsGroupIDKey] = d.executorsGroupID

	// TODO(sgotti) use go client listers instead of querying every time
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

	// TODO(sgotti) use go client listers instead of querying every time
	if d.useLeaseAPI {
		leaseClient := d.client.CoordinationV1().Leases(d.namespace)

		leases, err := leaseClient.List(metav1.ListOptions{LabelSelector: apilabels.SelectorFromSet(labels).String()})
		if err != nil {
			return err
		}
		for _, lease := range leases.Items {
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
				leaseClient.Delete(lease.Name, nil)
			}
		}
	} else {
		cmClient := d.client.CoreV1().ConfigMaps(d.namespace)

		cms, err := cmClient.List(metav1.ListOptions{LabelSelector: apilabels.SelectorFromSet(labels).String()})
		if err != nil {
			return err
		}
		for _, cm := range cms.Items {
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
				cmClient.Delete(cm.Name, nil)
			}
		}
	}
	return nil
}
